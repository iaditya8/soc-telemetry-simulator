package queue

import (
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
)

// OverflowPolicy dictates how the ring buffer behaves when capacity is reached.
type OverflowPolicy int

const (
	// OverflowPolicyBlock suspends the producer until consumer drains capacity (default).
	OverflowPolicyBlock OverflowPolicy = iota
	// OverflowPolicyDropOldest evicts the oldest enqueued event and releases its buffer.
	OverflowPolicyDropOldest
	// OverflowPolicyDropNewest rejects incoming event immediately and releases its buffer.
	OverflowPolicyDropNewest
)

// BackpressureState represents the multi-stage saturation level.
type BackpressureState int

const (
	// BackpressureNormal indicates <70% queue depth (unthrottled).
	BackpressureNormal BackpressureState = iota
	// BackpressureWarning indicates 70%-95% queue depth (adaptive micro-sleep throttling).
	BackpressureWarning
	// BackpressureCritical indicates >95% queue depth (strict block or drop).
	BackpressureCritical
)

// String returns human-readable name of the backpressure state.
func (s BackpressureState) String() string {
	switch s {
	case BackpressureNormal:
		return "NORMAL (<70%)"
	case BackpressureWarning:
		return "WARNING (70-95%)"
	case BackpressureCritical:
		return "CRITICAL (>95%)"
	default:
		return "UNKNOWN"
	}
}

var (
	// ErrQueueFull is returned when policy is OverflowPolicyDropNewest and queue is saturated.
	ErrQueueFull = errors.New("queue: ring buffer is full and drop-newest policy is active")
	// ErrMemoryCapExceeded is returned when process heap allocation exceeds memory guardrail.
	ErrMemoryCapExceeded = errors.New("queue: emergency memory guardrail cap exceeded")
)

// RingBufferConfig configures bounded ring buffer and backpressure thresholds.
type RingBufferConfig struct {
	Capacity              int            // Max events in ring (default: 50,000)
	OverflowPolicy        OverflowPolicy // Overflow behavior
	WarningThreshold      float64        // Warning backpressure threshold ratio (default: 0.70)
	CriticalThreshold     float64        // Critical backpressure threshold ratio (default: 0.95)
	MaxMemoryBytes        uint64         // Hard RAM guardrail cap (default: 500 MB)
	AdaptiveThrottleDelay time.Duration  // Delay injected in warning state (default: 50 microseconds)
}

// QueueStats captures real-time queue depth and accounting metrics.
type QueueStats struct {
	Enqueued        uint64
	Dequeued        uint64
	Dropped         uint64
	Throttled       uint64
	Depth           int
	Capacity        int
	FillRatio       float64
	State           BackpressureState
	HeapAllocBytes  uint64
}

// RingBuffer implements a bounded, circular, thread-safe queue holding *buffer.ByteBuffer pointers.
type RingBuffer struct {
	cfg       RingBufferConfig
	slots     []*buffer.ByteBuffer
	head      int // next write index
	tail      int // next read index
	count     int // current items in queue
	closed    bool
	mu        sync.Mutex
	notFull   *sync.Cond
	notEmpty  *sync.Cond

	// Statistics
	enqueued  uint64
	dequeued  uint64
	dropped   uint64
	throttled uint64
}

// NewRingBuffer allocates a bounded ring buffer with configured backpressure controls.
func NewRingBuffer(cfg RingBufferConfig) *RingBuffer {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 50000
	}
	if cfg.WarningThreshold <= 0 {
		cfg.WarningThreshold = 0.70
	}
	if cfg.CriticalThreshold <= 0 {
		cfg.CriticalThreshold = 0.95
	}
	if cfg.MaxMemoryBytes <= 0 {
		cfg.MaxMemoryBytes = 500 * 1024 * 1024 // 500 MB guardrail
	}
	if cfg.AdaptiveThrottleDelay <= 0 {
		cfg.AdaptiveThrottleDelay = 50 * time.Microsecond
	}

	rb := &RingBuffer{
		cfg:   cfg,
		slots: make([]*buffer.ByteBuffer, cfg.Capacity),
	}
	rb.notFull = sync.NewCond(&rb.mu)
	rb.notEmpty = sync.NewCond(&rb.mu)
	return rb
}

// Push enqueues a ByteBuffer pointer. It blocks or drops according to the configured OverflowPolicy.
func (rb *RingBuffer) Push(buf *buffer.ByteBuffer) error {
	rb.mu.Lock()

	// Check memory guardrail
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if m.Alloc > rb.cfg.MaxMemoryBytes {
		rb.mu.Unlock()
		atomic.AddUint64(&rb.dropped, 1)
		buf.Release()
		return ErrMemoryCapExceeded
	}

	if rb.closed {
		rb.mu.Unlock()
		buf.Release()
		return io.ErrClosedPipe
	}

	ratio := float64(rb.count) / float64(rb.cfg.Capacity)

	// Adaptive backpressure throttle in warning zone (70% - 95%)
	if ratio >= rb.cfg.WarningThreshold && ratio < rb.cfg.CriticalThreshold {
		atomic.AddUint64(&rb.throttled, 1)
		delay := rb.cfg.AdaptiveThrottleDelay
		rb.mu.Unlock()
		time.Sleep(delay)
		rb.mu.Lock()
		if rb.closed {
			rb.mu.Unlock()
			buf.Release()
			return io.ErrClosedPipe
		}
	}

	// Handle queue capacity saturation
	for rb.count == rb.cfg.Capacity {
		switch rb.cfg.OverflowPolicy {
		case OverflowPolicyBlock:
			rb.notFull.Wait()
			if rb.closed {
				rb.mu.Unlock()
				buf.Release()
				return io.ErrClosedPipe
			}

		case OverflowPolicyDropNewest:
			atomic.AddUint64(&rb.dropped, 1)
			rb.mu.Unlock()
			buf.Release()
			return ErrQueueFull

		case OverflowPolicyDropOldest:
			// Evict oldest item
			old := rb.slots[rb.tail]
			rb.slots[rb.tail] = nil
			rb.tail = (rb.tail + 1) % rb.cfg.Capacity
			rb.count--
			atomic.AddUint64(&rb.dropped, 1)
			if old != nil {
				old.Release()
			}
		}
	}

	// Enqueue new buffer
	rb.slots[rb.head] = buf
	rb.head = (rb.head + 1) % rb.cfg.Capacity
	rb.count++
	atomic.AddUint64(&rb.enqueued, 1)

	rb.notEmpty.Signal()
	rb.mu.Unlock()
	return nil
}

// Pop dequeues the next available ByteBuffer pointer. Blocks if empty until closed.
func (rb *RingBuffer) Pop() (*buffer.ByteBuffer, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for rb.count == 0 {
		if rb.closed {
			return nil, io.EOF
		}
		rb.notEmpty.Wait()
	}

	buf := rb.slots[rb.tail]
	rb.slots[rb.tail] = nil // Avoid memory retention
	rb.tail = (rb.tail + 1) % rb.cfg.Capacity
	rb.count--
	atomic.AddUint64(&rb.dequeued, 1)

	rb.notFull.Signal()
	return buf, nil
}

// TryPop attempts a non-blocking dequeue. Returns nil if empty.
func (rb *RingBuffer) TryPop() (*buffer.ByteBuffer, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.count == 0 {
		if rb.closed {
			return nil, io.EOF
		}
		return nil, nil
	}

	buf := rb.slots[rb.tail]
	rb.slots[rb.tail] = nil
	rb.tail = (rb.tail + 1) % rb.cfg.Capacity
	rb.count--
	atomic.AddUint64(&rb.dequeued, 1)

	rb.notFull.Signal()
	return buf, nil
}

// Close gracefully marks the ring buffer closed and wakes all waiting producers and consumers.
func (rb *RingBuffer) Close() error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.closed {
		return nil
	}
	rb.closed = true
	rb.notFull.Broadcast()
	rb.notEmpty.Broadcast()
	return nil
}

// Stats returns a snapshot of queue utilization, backpressure level, and memory allocation.
func (rb *RingBuffer) Stats() QueueStats {
	rb.mu.Lock()
	depth := rb.count
	cap := rb.cfg.Capacity
	rb.mu.Unlock()

	ratio := float64(depth) / float64(cap)
	var state BackpressureState
	if ratio >= rb.cfg.CriticalThreshold {
		state = BackpressureCritical
	} else if ratio >= rb.cfg.WarningThreshold {
		state = BackpressureWarning
	} else {
		state = BackpressureNormal
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return QueueStats{
		Enqueued:       atomic.LoadUint64(&rb.enqueued),
		Dequeued:       atomic.LoadUint64(&rb.dequeued),
		Dropped:        atomic.LoadUint64(&rb.dropped),
		Throttled:      atomic.LoadUint64(&rb.throttled),
		Depth:          depth,
		Capacity:       cap,
		FillRatio:      ratio,
		State:          state,
		HeapAllocBytes: m.Alloc,
	}
}

// Len returns current number of buffered items.
func (rb *RingBuffer) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.count
}
