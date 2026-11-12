package ledger

import (
	"sync"
	"testing"
)

func TestAccountingInvariantsPassing(t *testing.T) {
	acc := NewAccountingEngine()

	// 100 Normal, 20 Suspicious = 120 Generated
	acc.RecordGenerated("windows", "", 1, ClassNormal, 100)
	acc.RecordGenerated("linux", "T1110.001", 2, ClassSuspicious, 20)

	// 110 Enqueued, 10 Dropped = 120
	acc.RecordEnqueued("windows", 95)
	acc.RecordEnqueued("linux", 15)
	acc.RecordDropped("windows", 5)
	acc.RecordDropped("linux", 5)

	// 110 Submitted
	acc.RecordSubmitted("windows", 95)
	acc.RecordSubmitted("linux", 15)

	// 100 Acknowledged, 5 Rejected, 5 Failed = 110
	acc.RecordAcknowledged("windows", 90)
	acc.RecordAcknowledged("linux", 10)
	acc.RecordRejected("windows", 3)
	acc.RecordRejected("linux", 2)
	acc.RecordFailed("windows", 2)
	acc.RecordFailed("linux", 3)

	// 15 Network Retries (should NOT increase Generated)
	acc.RecordRetry("windows", 10)
	acc.RecordRetry("linux", 5)

	if err := acc.ValidateInvariants(); err != nil {
		t.Fatalf("expected valid invariants, got: %v", err)
	}

	snap := acc.Snapshot()
	if snap.TotalGenerated != 120 {
		t.Errorf("expected 120 generated, got %d", snap.TotalGenerated)
	}
	if snap.TotalRetries != 15 {
		t.Errorf("expected 15 retries, got %d", snap.TotalRetries)
	}
	if snap.TotalAcknowledged != 100 {
		t.Errorf("expected 100 acknowledged, got %d", snap.TotalAcknowledged)
	}
	if snap.TotalDropped != 10 {
		t.Errorf("expected 10 dropped, got %d", snap.TotalDropped)
	}
}

func TestAccountingInvariantsViolation(t *testing.T) {
	acc := NewAccountingEngine()

	// Record 50 generated
	acc.RecordGenerated("windows", "", 1, ClassNormal, 50)

	// Artificially report 60 enqueued (more than generated)
	acc.RecordEnqueued("windows", 60)

	err := acc.ValidateInvariants()
	if err == nil {
		t.Fatal("expected invariant violation error when Enqueued > Generated")
	}
}

func TestAccountingConcurrencyStress(t *testing.T) {
	acc := NewAccountingEngine()

	const workers = 16
	const eventsPerWorker = 2000
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			source := "windows"
			if id%2 == 1 {
				source = "linux"
			}
			scenario := ""
			class := ClassNormal
			if id%4 == 0 {
				scenario = "T1046"
				class = ClassSuspicious
			}

			for i := 0; i < eventsPerWorker; i++ {
				acc.RecordGenerated(source, scenario, uint32(id), class, 1)
				acc.RecordEnqueued(source, 1)
				acc.RecordSubmitted(source, 1)
				acc.RecordAcknowledged(source, 1)
			}
		}(w)
	}

	wg.Wait()

	if err := acc.ValidateInvariants(); err != nil {
		t.Fatalf("concurrent invariants validation failed: %v", err)
	}

	snap := acc.Snapshot()
	expectedTotal := uint64(workers * eventsPerWorker)
	if snap.TotalGenerated != expectedTotal {
		t.Errorf("expected %d generated, got %d", expectedTotal, snap.TotalGenerated)
	}
	if snap.TotalAcknowledged != expectedTotal {
		t.Errorf("expected %d acknowledged, got %d", expectedTotal, snap.TotalAcknowledged)
	}
}

func BenchmarkAccountingRecord(b *testing.B) {
	acc := NewAccountingEngine()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			acc.RecordGenerated("windows", "T1110.001", 1, ClassSuspicious, 1)
			acc.RecordEnqueued("windows", 1)
			acc.RecordSubmitted("windows", 1)
			acc.RecordAcknowledged("windows", 1)
		}
	})
}
