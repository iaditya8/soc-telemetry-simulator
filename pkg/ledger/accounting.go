package ledger

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// AccountingSnapshot provides an immutable snapshot of simulator delivery metrics.
type AccountingSnapshot struct {
	TotalGenerated    uint64
	TotalNormal       uint64
	TotalSuspicious   uint64
	TotalEnqueued     uint64
	TotalSubmitted    uint64
	TotalAcknowledged uint64
	TotalRejected     uint64
	TotalFailed       uint64
	TotalUnknown      uint64
	TotalDropped      uint64
	TotalRetries      uint64

	BySourceFamily map[string]SourceBreakdown
	ByScenario     map[string]uint64
	ByEndpoint     map[uint32]uint64
}

// SourceBreakdown contains delivery numbers for an individual telemetry source family.
type SourceBreakdown struct {
	Generated    uint64
	Enqueued     uint64
	Submitted    uint64
	Acknowledged uint64
	Rejected     uint64
	Failed       uint64
	Dropped      uint64
	Retries      uint64
}

// AccountingEngine manages multi-dimensional atomic counters and enforces delivery invariants.
type AccountingEngine struct {
	// Top-level atomic counters
	generated    uint64
	normal       uint64
	suspicious   uint64
	enqueued     uint64
	submitted    uint64
	acknowledged uint64
	rejected     uint64
	failed       uint64
	unknown      uint64
	dropped      uint64
	retries      uint64

	mu         sync.RWMutex
	bySource   map[string]*SourceBreakdown
	byScenario map[string]*uint64
	byEndpoint map[uint32]*uint64
}

// NewAccountingEngine initializes the delivery accounting engine.
func NewAccountingEngine() *AccountingEngine {
	return &AccountingEngine{
		bySource:   make(map[string]*SourceBreakdown),
		byScenario: make(map[string]*uint64),
		byEndpoint: make(map[uint32]*uint64),
	}
}

// RecordGenerated registers newly generated events.
func (a *AccountingEngine) RecordGenerated(source string, scenario string, endpointID uint32, class Classification, count uint64) {
	if count == 0 {
		return
	}

	atomic.AddUint64(&a.generated, count)
	if class == ClassSuspicious {
		atomic.AddUint64(&a.suspicious, count)
	} else {
		atomic.AddUint64(&a.normal, count)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Source family breakdown
	sb, ok := a.bySource[source]
	if !ok {
		sb = &SourceBreakdown{}
		a.bySource[source] = sb
	}
	sb.Generated += count

	// Scenario breakdown
	if scenario != "" {
		sc, ok := a.byScenario[scenario]
		if !ok {
			sc = new(uint64)
			a.byScenario[scenario] = sc
		}
		*sc += count
	}

	// Endpoint breakdown
	ep, ok := a.byEndpoint[endpointID]
	if !ok {
		ep = new(uint64)
		a.byEndpoint[endpointID] = ep
	}
	*ep += count
}

// RecordEnqueued tallies events admitted into the bounded transmission queue.
func (a *AccountingEngine) RecordEnqueued(source string, count uint64) {
	if count == 0 {
		return
	}
	atomic.AddUint64(&a.enqueued, count)

	a.mu.Lock()
	if sb, ok := a.bySource[source]; ok {
		sb.Enqueued += count
	}
	a.mu.Unlock()
}

// RecordSubmitted tallies events transmitted onto the wire by forwarder adapters.
func (a *AccountingEngine) RecordSubmitted(source string, count uint64) {
	if count == 0 {
		return
	}
	atomic.AddUint64(&a.submitted, count)

	a.mu.Lock()
	if sb, ok := a.bySource[source]; ok {
		sb.Submitted += count
	}
	a.mu.Unlock()
}

// RecordAcknowledged tallies events confirmed received by the destination receiver.
func (a *AccountingEngine) RecordAcknowledged(source string, count uint64) {
	if count == 0 {
		return
	}
	atomic.AddUint64(&a.acknowledged, count)

	a.mu.Lock()
	if sb, ok := a.bySource[source]; ok {
		sb.Acknowledged += count
	}
	a.mu.Unlock()
}

// RecordRejected tallies events rejected by the destination (e.g. HTTP 4xx, bad auth, bad formatting).
func (a *AccountingEngine) RecordRejected(source string, count uint64) {
	if count == 0 {
		return
	}
	atomic.AddUint64(&a.rejected, count)

	a.mu.Lock()
	if sb, ok := a.bySource[source]; ok {
		sb.Rejected += count
	}
	a.mu.Unlock()
}

// RecordFailed tallies events that failed delivery due to server errors (HTTP 5xx) or socket aborts.
func (a *AccountingEngine) RecordFailed(source string, count uint64) {
	if count == 0 {
		return
	}
	atomic.AddUint64(&a.failed, count)

	a.mu.Lock()
	if sb, ok := a.bySource[source]; ok {
		sb.Failed += count
	}
	a.mu.Unlock()
}

// RecordUnknown tallies events whose outcome cannot be determined (e.g. fire-and-forget UDP).
func (a *AccountingEngine) RecordUnknown(count uint64) {
	if count == 0 {
		return
	}
	atomic.AddUint64(&a.unknown, count)
}

// RecordDropped tallies events dropped locally due to queue overflow backpressure.
func (a *AccountingEngine) RecordDropped(source string, count uint64) {
	if count == 0 {
		return
	}
	atomic.AddUint64(&a.dropped, count)

	a.mu.Lock()
	if sb, ok := a.bySource[source]; ok {
		sb.Dropped += count
	}
	a.mu.Unlock()
}

// RecordRetry records a network retry attempt. Crucially, retries DO NOT inflate TotalGenerated.
func (a *AccountingEngine) RecordRetry(source string, count uint64) {
	if count == 0 {
		return
	}
	atomic.AddUint64(&a.retries, count)

	a.mu.Lock()
	if sb, ok := a.bySource[source]; ok {
		sb.Retries += count
	}
	a.mu.Unlock()
}

// ValidateInvariants verifies mathematical consistency across all delivery states.
func (a *AccountingEngine) ValidateInvariants() error {
	gen := atomic.LoadUint64(&a.generated)
	norm := atomic.LoadUint64(&a.normal)
	susp := atomic.LoadUint64(&a.suspicious)
	enq := atomic.LoadUint64(&a.enqueued)
	sub := atomic.LoadUint64(&a.submitted)
	ack := atomic.LoadUint64(&a.acknowledged)
	rej := atomic.LoadUint64(&a.rejected)
	fail := atomic.LoadUint64(&a.failed)
	unk := atomic.LoadUint64(&a.unknown)
	drop := atomic.LoadUint64(&a.dropped)

	// Invariant 1: TotalGenerated == Normal + Suspicious
	if gen != norm+susp {
		return fmt.Errorf("invariant violation: Generated (%d) != Normal (%d) + Suspicious (%d)",
			gen, norm, susp)
	}

	// Invariant 2: TotalEnqueued + TotalDropped <= TotalGenerated
	if enq+drop > gen {
		return fmt.Errorf("invariant violation: Enqueued (%d) + Dropped (%d) > Generated (%d)",
			enq, drop, gen)
	}

	// Invariant 3: TotalSubmitted <= TotalEnqueued
	if sub > enq {
		return fmt.Errorf("invariant violation: Submitted (%d) > Enqueued (%d)",
			sub, enq)
	}

	// Invariant 4: Acknowledged + Rejected + Failed + Unknown <= TotalSubmitted
	resolved := ack + rej + fail + unk
	if resolved > sub {
		return fmt.Errorf("invariant violation: Resolved outcomes (Ack:%d + Rej:%d + Fail:%d + Unk:%d = %d) > Submitted (%d)",
			ack, rej, fail, unk, resolved, sub)
	}

	return nil
}

// Snapshot returns a point-in-time copy of all accounting metrics.
func (a *AccountingEngine) Snapshot() AccountingSnapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()

	sources := make(map[string]SourceBreakdown, len(a.bySource))
	for k, v := range a.bySource {
		sources[k] = *v
	}

	scenarios := make(map[string]uint64, len(a.byScenario))
	for k, v := range a.byScenario {
		scenarios[k] = *v
	}

	endpoints := make(map[uint32]uint64, len(a.byEndpoint))
	for k, v := range a.byEndpoint {
		endpoints[k] = *v
	}

	return AccountingSnapshot{
		TotalGenerated:    atomic.LoadUint64(&a.generated),
		TotalNormal:       atomic.LoadUint64(&a.normal),
		TotalSuspicious:   atomic.LoadUint64(&a.suspicious),
		TotalEnqueued:     atomic.LoadUint64(&a.enqueued),
		TotalSubmitted:    atomic.LoadUint64(&a.submitted),
		TotalAcknowledged: atomic.LoadUint64(&a.acknowledged),
		TotalRejected:     atomic.LoadUint64(&a.rejected),
		TotalFailed:       atomic.LoadUint64(&a.failed),
		TotalUnknown:      atomic.LoadUint64(&a.unknown),
		TotalDropped:      atomic.LoadUint64(&a.dropped),
		TotalRetries:      atomic.LoadUint64(&a.retries),
		BySourceFamily:    sources,
		ByScenario:        scenarios,
		ByEndpoint:        endpoints,
	}
}
