package queue

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
)

func TestRingBufferFIFO(t *testing.T) {
	rb := NewRingBuffer(RingBufferConfig{
		Capacity: 100,
	})
	defer rb.Close()

	for i := 0; i < 50; i++ {
		b := buffer.GetBuffer()
		b.AppendInt(int64(i))
		if err := rb.Push(b); err != nil {
			t.Fatalf("push %d failed: %v", i, err)
		}
	}

	for i := 0; i < 50; i++ {
		b, err := rb.Pop()
		if err != nil {
			t.Fatalf("pop %d failed: %v", i, err)
		}
		expected := int64(i)
		buf := buffer.GetBuffer()
		buf.AppendInt(expected)
		if b.String() != buf.String() {
			t.Errorf("expected %s, got %s", buf.String(), b.String())
		}
		buf.Release()
		b.Release()
	}

	stats := rb.Stats()
	if stats.Enqueued != 50 || stats.Dequeued != 50 {
		t.Errorf("stats mismatch: enqueued=%d, dequeued=%d", stats.Enqueued, stats.Dequeued)
	}
}

func TestRingBufferBlocking(t *testing.T) {
	rb := NewRingBuffer(RingBufferConfig{
		Capacity:       5,
		OverflowPolicy: OverflowPolicyBlock,
	})
	defer rb.Close()

	const total = 20
	var received []int
	var mu sync.Mutex
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < total; i++ {
			b, err := rb.Pop()
			if err != nil {
				return
			}
			mu.Lock()
			received = append(received, i)
			mu.Unlock()
			b.Release()
		}
	}()

	for i := 0; i < total; i++ {
		b := buffer.GetBuffer()
		b.AppendInt(int64(i))
		if err := rb.Push(b); err != nil {
			t.Fatalf("push %d failed: %v", i, err)
		}
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for consumer")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != total {
		t.Fatalf("expected %d received items, got %d", total, len(received))
	}
}

func TestRingBufferDropNewest(t *testing.T) {
	rb := NewRingBuffer(RingBufferConfig{
		Capacity:       10,
		OverflowPolicy: OverflowPolicyDropNewest,
	})
	defer rb.Close()

	for i := 0; i < 10; i++ {
		b := buffer.GetBuffer()
		b.AppendInt(int64(i))
		if err := rb.Push(b); err != nil {
			t.Fatalf("push %d should succeed: %v", i, err)
		}
	}

	// 11th through 15th push should fail with ErrQueueFull and release buffer
	for i := 10; i < 15; i++ {
		b := buffer.GetBuffer()
		b.AppendInt(int64(i))
		err := rb.Push(b)
		if !errors.Is(err, ErrQueueFull) {
			t.Fatalf("expected ErrQueueFull on push %d, got %v", i, err)
		}
	}

	stats := rb.Stats()
	if stats.Enqueued != 10 {
		t.Errorf("expected 10 enqueued, got %d", stats.Enqueued)
	}
	if stats.Dropped != 5 {
		t.Errorf("expected 5 dropped, got %d", stats.Dropped)
	}
	if rb.Len() != 10 {
		t.Errorf("expected queue length 10, got %d", rb.Len())
	}
}

func TestRingBufferDropOldest(t *testing.T) {
	rb := NewRingBuffer(RingBufferConfig{
		Capacity:       5,
		OverflowPolicy: OverflowPolicyDropOldest,
	})
	defer rb.Close()

	for i := 0; i < 10; i++ {
		b := buffer.GetBuffer()
		b.AppendInt(int64(i))
		if err := rb.Push(b); err != nil {
			t.Fatalf("push %d failed: %v", i, err)
		}
	}

	stats := rb.Stats()
	if stats.Enqueued != 10 {
		t.Errorf("expected 10 total enqueued, got %d", stats.Enqueued)
	}
	if stats.Dropped != 5 {
		t.Errorf("expected 5 dropped, got %d", stats.Dropped)
	}

	// Dequeued items should be the latest 5: 5, 6, 7, 8, 9
	for expected := 5; expected < 10; expected++ {
		b, err := rb.Pop()
		if err != nil {
			t.Fatalf("pop failed: %v", err)
		}
		expectedBuf := buffer.GetBuffer()
		expectedBuf.AppendInt(int64(expected))
		if b.String() != expectedBuf.String() {
			t.Errorf("expected %s, got %s", expectedBuf.String(), b.String())
		}
		expectedBuf.Release()
		b.Release()
	}
}

func TestRingBufferBackpressureStates(t *testing.T) {
	rb := NewRingBuffer(RingBufferConfig{
		Capacity:              100,
		WarningThreshold:      0.70,
		CriticalThreshold:     0.95,
		AdaptiveThrottleDelay: 1 * time.Microsecond,
	})
	defer rb.Close()

	if rb.Stats().State != BackpressureNormal {
		t.Errorf("expected initial state Normal, got %v", rb.Stats().State)
	}

	// Fill to 75 (Warning)
	for i := 0; i < 75; i++ {
		b := buffer.GetBuffer()
		_ = rb.Push(b)
	}

	if rb.Stats().State != BackpressureWarning {
		t.Errorf("expected state Warning at 75%% depth, got %v", rb.Stats().State)
	}

	// Fill to 96 (Critical)
	for i := 75; i < 96; i++ {
		b := buffer.GetBuffer()
		_ = rb.Push(b)
	}

	if rb.Stats().State != BackpressureCritical {
		t.Errorf("expected state Critical at 96%% depth, got %v", rb.Stats().State)
	}
}

func TestRingBufferClose(t *testing.T) {
	rb := NewRingBuffer(RingBufferConfig{
		Capacity: 10,
	})

	popDone := make(chan struct{})
	go func() {
		defer close(popDone)
		_, err := rb.Pop()
		if !errors.Is(err, io.EOF) {
			t.Errorf("expected io.EOF on closed pop, got %v", err)
		}
	}()

	time.Sleep(10 * time.Millisecond)
	_ = rb.Close()

	select {
	case <-popDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Pop to return after Close")
	}

	b := buffer.GetBuffer()
	err := rb.Push(b)
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("expected io.ErrClosedPipe on closed push, got %v", err)
	}
	// Note: Push releases buffer on error
}

func BenchmarkRingBufferThroughput(b *testing.B) {
	rb := NewRingBuffer(RingBufferConfig{
		Capacity:       10000,
		OverflowPolicy: OverflowPolicyBlock,
	})
	defer rb.Close()

	go func() {
		for {
			buf, err := rb.Pop()
			if err != nil {
				return
			}
			buf.Release()
		}
	}()

	for b.Loop() {
		buf := buffer.GetBuffer()
		buf.AppendString("benchmark message")
		_ = rb.Push(buf)
	}
}
