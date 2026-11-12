package ledger

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestXXHash64Correctness(t *testing.T) {
	// Standard xxHash64 test vectors
	tests := []struct {
		input    string
		seed     uint64
		expected uint64
	}{
		{"", 0, 0xEF46DB3751D8E999},
		{"a", 0, 0xD24EC4F1A98C6E5B},
		{"12345678901234567890123456789012", 0, 0x40FD1AA52D98274C},
		{"The quick brown fox jumps over the lazy dog", 0, 0x0B242D361FDA71BC},
	}

	for _, tc := range tests {
		hash := XXHash64([]byte(tc.input), tc.seed)
		if hash != tc.expected {
			t.Errorf("input %q: expected 0x%X, got 0x%X", tc.input, tc.expected, hash)
		}
	}
}

func TestRingLedgerMonotonicSequence(t *testing.T) {
	rl := NewRingLedger(50000)

	const total = 10000
	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)

	seqs := make([]uint64, total)
	var mu sync.Mutex

	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < total/workers; i++ {
				ts := uint64(time.Now().UnixNano())
				hash := XXHash64(fmt.Appendf(nil, "worker-%d-event-%d", workerID, i), 0)
				seq := rl.Record(hash, ts, uint32(workerID), 4624, ClassNormal)

				mu.Lock()
				seqs = append(seqs, seq)
				mu.Unlock()
			}
		}(w)
	}

	wg.Wait()

	if rl.TotalRecorded() != total {
		t.Fatalf("expected total recorded %d, got %d", total, rl.TotalRecorded())
	}

	// Verify all entries can be retrieved
	for s := uint64(1); s <= total; s++ {
		entry, found := rl.Get(s)
		if !found {
			t.Fatalf("sequence %d not found in ledger", s)
		}
		if entry.SequenceID != s {
			t.Fatalf("sequence mismatch: expected %d, got %d", s, entry.SequenceID)
		}
		if entry.Class != ClassNormal {
			t.Errorf("class mismatch: expected ClassNormal, got %v", entry.Class)
		}
	}
}

func TestRingLedgerDeliveryStateTransitions(t *testing.T) {
	rl := NewRingLedger(100)

	seq := rl.Record(0xDEADBEEF, uint64(time.Now().UnixNano()), 1, 100, ClassSuspicious)

	entry, found := rl.Get(seq)
	if !found || entry.Delivery != StateGenerated {
		t.Fatalf("expected initial state StateGenerated, got %v", entry.Delivery)
	}

	// Transition to Enqueued -> Submitted -> Acknowledged
	if !rl.UpdateDelivery(seq, StateEnqueued) {
		t.Fatal("failed to update to Enqueued")
	}
	if !rl.UpdateDelivery(seq, StateSubmitted) {
		t.Fatal("failed to update to Submitted")
	}
	if !rl.UpdateDelivery(seq, StateAcknowledged) {
		t.Fatal("failed to update to Acknowledged")
	}

	entry, _ = rl.Get(seq)
	if entry.Delivery != StateAcknowledged {
		t.Errorf("expected final state StateAcknowledged, got %v", entry.Delivery)
	}

	sum := rl.Summary()
	if sum.TotalEvents != 1 || sum.SuspiciousEvents != 1 || sum.AckedCount != 1 {
		t.Errorf("summary mismatch: %+v", sum)
	}
}

func TestRingLedgerCircularOverwrite(t *testing.T) {
	rl := NewRingLedger(50) // Small ring

	for i := 1; i <= 100; i++ {
		_ = rl.Record(uint64(i), uint64(i*1000), uint32(i), 1, ClassNormal)
	}

	// First 50 should be overwritten
	_, found := rl.Get(1)
	if found {
		t.Error("expected seq 1 to be overwritten and not found")
	}

	// Last 50 (51..100) should be available
	entry, found := rl.Get(100)
	if !found {
		t.Fatal("expected seq 100 to be found")
	}
	if entry.Fingerprint != 100 {
		t.Errorf("expected fingerprint 100, got %d", entry.Fingerprint)
	}
}

func BenchmarkXXHash64(b *testing.B) {
	sample := []byte("<86>Nov 12 05:00:00 srv01 sshd[14205]: Accepted publickey for sysadmin from 10.100.1.25 port 54321 ssh2: RSA SHA256:4t7Xg617B5B6x44k9Z1X2Y3Z\n")

	for b.Loop() {
		_ = XXHash64(sample, 0)
	}
}

func BenchmarkRingLedgerRecord(b *testing.B) {
	rl := NewRingLedger(1000000)
	ts := uint64(time.Now().UnixNano())

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = rl.Record(0xAABBCCDDEEFF0011, ts, 1, 4624, ClassNormal)
		}
	})
}
