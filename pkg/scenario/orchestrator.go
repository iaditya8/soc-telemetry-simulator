package scenario

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

// OrchestratorConfig configures scenario blending and intensity.
type OrchestratorConfig struct {
	SuspiciousRatio float64 // e.g. 0.05 for 5% suspicious
	EnabledTechniques []string
}

// Orchestrator manages concurrent attack state machines and ratio blending.
type Orchestrator struct {
	cfg        OrchestratorConfig
	fleetMgr   *fleet.FleetManager
	formatters *Formatters

	mu              sync.Mutex
	activeScenarios []Scenario

	totalCount      uint64
	suspiciousCount uint64
	normalCount     uint64
}

// NewOrchestrator constructs a scenario orchestrator.
func NewOrchestrator(cfg OrchestratorConfig, fm *fleet.FleetManager, fmts *Formatters) *Orchestrator {
	if cfg.SuspiciousRatio < 0 {
		cfg.SuspiciousRatio = 0
	}
	if cfg.SuspiciousRatio > 1.0 {
		cfg.SuspiciousRatio = 1.0
	}
	return &Orchestrator{
		cfg:             cfg,
		fleetMgr:        fm,
		formatters:      fmts,
		activeScenarios: make([]Scenario, 0, 16),
	}
}

// Formatters returns the bundled formatters.
func (o *Orchestrator) Formatters() *Formatters {
	return o.formatters
}

// ShouldEmitSuspicious checks if the next event should be an attack campaign event.
func (o *Orchestrator) ShouldEmitSuspicious(rng *rand.Rand) bool {
	if o.cfg.SuspiciousRatio <= 0 {
		atomic.AddUint64(&o.totalCount, 1)
		atomic.AddUint64(&o.normalCount, 1)
		return false
	}
	if o.cfg.SuspiciousRatio >= 1.0 {
		atomic.AddUint64(&o.totalCount, 1)
		atomic.AddUint64(&o.suspiciousCount, 1)
		return true
	}

	val := rng.Float64()
	isSuspicious := val < o.cfg.SuspiciousRatio

	atomic.AddUint64(&o.totalCount, 1)
	if isSuspicious {
		atomic.AddUint64(&o.suspiciousCount, 1)
	} else {
		atomic.AddUint64(&o.normalCount, 1)
	}
	return isSuspicious
}

// StepSuspicious steps an active scenario or spawns a new one into the buffer.
func (o *Orchestrator) StepSuspicious(buf *buffer.ByteBuffer, now time.Time, seq uint64, rng *rand.Rand) {
	o.mu.Lock()
	// Filter out completed scenarios
	active := make([]Scenario, 0, len(o.activeScenarios))
	for _, sc := range o.activeScenarios {
		if !sc.IsCompleted() {
			active = append(active, sc)
		}
	}
	o.activeScenarios = active

	// If no active scenarios, spawn a new attack campaign
	if len(o.activeScenarios) == 0 {
		sc := o.spawnRandomScenario(rng)
		if sc != nil {
			o.activeScenarios = append(o.activeScenarios, sc)
		}
	}

	if len(o.activeScenarios) == 0 {
		o.mu.Unlock()
		return
	}

	// Pick a scenario to step
	idx := rng.Intn(len(o.activeScenarios))
	selected := o.activeScenarios[idx]
	o.mu.Unlock()

	selected.Step(buf, now, seq, rng)
}

func (o *Orchestrator) spawnRandomScenario(rng *rand.Rand) Scenario {
	roll := rng.Intn(6)
	switch roll {
	case 0:
		// T1110.001 Brute force
		wks, _ := o.fleetMgr.SampleByRole(fleet.RoleWorkstation)
		if wks == nil {
			wks = o.fleetMgr.SampleWeighted()
		}
		if wks == nil {
			return nil
		}
		return NewBruteForceScenario("198.51.100.45", "administrator", wks, 15, o.formatters)

	case 1:
		// T1046 Port scan
		fw, _ := o.fleetMgr.SampleByRole(fleet.RoleFirewall)
		web, _ := o.fleetMgr.SampleByRole(fleet.RoleWebServer)
		if fw == nil || web == nil {
			return nil
		}
		return NewPortScanScenario("203.0.113.88", web, fw, o.formatters)

	case 2:
		// T1071.004 DNS C2 Beaconing
		dns, _ := o.fleetMgr.SampleByRole(fleet.RoleDNSServer)
		wks, _ := o.fleetMgr.SampleByRole(fleet.RoleWorkstation)
		if dns == nil || wks == nil {
			return nil
		}
		return NewDNSBeaconingScenario("darkmesh-c2.cc", wks, dns, 15, o.formatters)

	case 3:
		// T1059.001 Obfuscated PowerShell
		wks, _ := o.fleetMgr.SampleByRole(fleet.RoleWorkstation)
		if wks == nil {
			wks = o.fleetMgr.SampleWeighted()
		}
		if wks == nil {
			return nil
		}
		return NewObfuscatedPowerShellScenario(wks, o.formatters)

	case 4:
		// T1078.004 Cloud Account Compromise (AWS CloudTrail)
		ep, _ := o.fleetMgr.SampleByRole(fleet.RoleCloudAccount)
		if ep == nil {
			ep = o.fleetMgr.SampleWeighted()
		}
		if ep == nil {
			return nil
		}
		return NewCloudAccountCompromiseScenario("198.51.100.199", "admin_cloud", ep, 5, o.formatters)

	default:
		// T1110.003 Cloud Password Spraying (Microsoft Entra ID)
		ep, _ := o.fleetMgr.SampleByRole(fleet.RoleCloudAccount)
		if ep == nil {
			ep = o.fleetMgr.SampleWeighted()
		}
		if ep == nil {
			return nil
		}
		domain := "corp.onmicrosoft.com"
		if ep.Domain != "" {
			domain = ep.Domain
		}
		return NewCloudPasswordSprayScenario("185.220.101.5", domain, ep, 10, o.formatters)
	}
}

// Stats returns generation ratio metrics.
func (o *Orchestrator) Stats() (total, normal, suspicious uint64, ratio float64) {
	tot := atomic.LoadUint64(&o.totalCount)
	norm := atomic.LoadUint64(&o.normalCount)
	susp := atomic.LoadUint64(&o.suspiciousCount)
	var r float64
	if tot > 0 {
		r = float64(susp) / float64(tot)
	}
	return tot, norm, susp, r
}
