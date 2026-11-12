package ledger

import (
	"sync"
	"sync/atomic"
)

// Classification categorizes an event as benign enterprise traffic or threat activity.
type Classification uint8

const (
	ClassNormal Classification = iota
	ClassSuspicious
)

func (c Classification) String() string {
	switch c {
	case ClassNormal:
		return "Normal"
	case ClassSuspicious:
		return "Suspicious"
	default:
		return "Unknown"
	}
}

// DeliveryState tracks the exact lifecycle stage of an individual event.
type DeliveryState uint8

const (
	StateGenerated DeliveryState = iota
	StateEnqueued
	StateSubmitted
	StateAcknowledged
	StateDropped
	StateFailed
)

func (d DeliveryState) String() string {
	switch d {
	case StateGenerated:
		return "Generated"
	case StateEnqueued:
		return "Enqueued"
	case StateSubmitted:
		return "Submitted"
	case StateAcknowledged:
		return "Acknowledged"
	case StateDropped:
		return "Dropped"
	case StateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// Entry is a 32-byte compact in-memory event audit record.
// Memory footprint is exactly 32 MB per 1,000,000 events.
type Entry struct {
	SequenceID  uint64         // Monotonically increasing 1-based sequence index
	Fingerprint uint64         // xxHash64 payload fingerprint
	Timestamp   uint64         // Generation timestamp (UnixNano)
	EndpointID  uint32         // Logical fleet endpoint index
	SourceType  uint16         // Telemetry format / event type code
	Class       Classification // Normal (0) or Suspicious (1)
	Delivery    DeliveryState  // Ingestion lifecycle stage
}

// LedgerSummary aggregates high-level reconciliation counts.
type LedgerSummary struct {
	TotalEvents      uint64
	NormalEvents     uint64
	SuspiciousEvents uint64
	GeneratedCount   uint64
	EnqueuedCount    uint64
	SubmittedCount   uint64
	AckedCount       uint64
	DroppedCount     uint64
	FailedCount      uint64
	MemoryBytes      uint64
}

// RingLedger manages a bounded, high-speed circular memory ledger of audit entries.
type RingLedger struct {
	capacity uint64
	entries  []Entry
	seq      uint64
	mu       sync.RWMutex

	// Real-time atomic counters
	normalCount     uint64
	suspiciousCount uint64
	generatedCount  uint64
	enqueuedCount   uint64
	submittedCount  uint64
	ackedCount      uint64
	droppedCount    uint64
	failedCount     uint64
}

// NewRingLedger allocates an in-memory audit ledger with fixed slot capacity.
func NewRingLedger(capacity int) *RingLedger {
	if capacity <= 0 {
		capacity = 1000000 // 1 Million events = ~32 MB
	}

	return &RingLedger{
		capacity: uint64(capacity),
		entries:  make([]Entry, capacity),
	}
}

// Record inserts a newly generated event audit record into the ledger with zero heap allocations.
func (rl *RingLedger) Record(fingerprint uint64, timestamp uint64, endpointID uint32, sourceType uint16, class Classification) uint64 {
	seq := atomic.AddUint64(&rl.seq, 1)
	slot := (seq - 1) % rl.capacity

	entry := Entry{
		SequenceID:  seq,
		Fingerprint: fingerprint,
		Timestamp:   timestamp,
		EndpointID:  endpointID,
		SourceType:  sourceType,
		Class:       class,
		Delivery:    StateGenerated,
	}

	rl.mu.Lock()
	rl.entries[slot] = entry
	rl.mu.Unlock()

	atomic.AddUint64(&rl.generatedCount, 1)
	if class == ClassSuspicious {
		atomic.AddUint64(&rl.suspiciousCount, 1)
	} else {
		atomic.AddUint64(&rl.normalCount, 1)
	}

	return seq
}

// UpdateDelivery transitions the delivery state of a previously recorded event.
func (rl *RingLedger) UpdateDelivery(seqID uint64, state DeliveryState) bool {
	if seqID == 0 {
		return false
	}

	slot := (seqID - 1) % rl.capacity

	rl.mu.Lock()
	if rl.entries[slot].SequenceID != seqID {
		rl.mu.Unlock()
		return false // Entry was overwritten in circular ring
	}
	oldState := rl.entries[slot].Delivery
	rl.entries[slot].Delivery = state
	rl.mu.Unlock()

	// Adjust atomic state tallies
	switch state {
	case StateEnqueued:
		atomic.AddUint64(&rl.enqueuedCount, 1)
	case StateSubmitted:
		atomic.AddUint64(&rl.submittedCount, 1)
	case StateAcknowledged:
		atomic.AddUint64(&rl.ackedCount, 1)
	case StateDropped:
		atomic.AddUint64(&rl.droppedCount, 1)
	case StateFailed:
		atomic.AddUint64(&rl.failedCount, 1)
	}

	_ = oldState
	return true
}

// Get retrieves a recorded audit entry by its sequence ID.
func (rl *RingLedger) Get(seqID uint64) (Entry, bool) {
	if seqID == 0 {
		return Entry{}, false
	}

	slot := (seqID - 1) % rl.capacity

	rl.mu.RLock()
	entry := rl.entries[slot]
	rl.mu.RUnlock()

	if entry.SequenceID != seqID {
		return Entry{}, false
	}
	return entry, true
}

// TotalRecorded returns cumulative events registered in the ledger.
func (rl *RingLedger) TotalRecorded() uint64 {
	return atomic.LoadUint64(&rl.seq)
}

// Capacity returns the ring buffer slot capacity.
func (rl *RingLedger) Capacity() uint64 {
	return rl.capacity
}

// Summary calculates the delivery reconciliation overview.
func (rl *RingLedger) Summary() LedgerSummary {
	total := atomic.LoadUint64(&rl.seq)

	return LedgerSummary{
		TotalEvents:      total,
		NormalEvents:     atomic.LoadUint64(&rl.normalCount),
		SuspiciousEvents: atomic.LoadUint64(&rl.suspiciousCount),
		GeneratedCount:   atomic.LoadUint64(&rl.generatedCount),
		EnqueuedCount:    atomic.LoadUint64(&rl.enqueuedCount),
		SubmittedCount:   atomic.LoadUint64(&rl.submittedCount),
		AckedCount:       atomic.LoadUint64(&rl.ackedCount),
		DroppedCount:     atomic.LoadUint64(&rl.droppedCount),
		FailedCount:      atomic.LoadUint64(&rl.failedCount),
		MemoryBytes:      rl.capacity * 32, // Exactly 32 bytes per entry
	}
}
