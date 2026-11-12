package generator

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/formatter"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/scenario"
)

// Engine orchestrates high-volume log generation across fleet endpoints.
type Engine struct {
	cfg          config.SimulationConfig
	fleetMgr     *fleet.FleetManager
	scheduler    *Scheduler
	outChan      chan *ByteBuffer
	rng          *rand.Rand
	winFormatter   *formatter.WindowsXMLFormatter
	linuxFormatter *formatter.LinuxSyslogFormatter
	paFormatter    *formatter.PaloAltoFormatter
	dnsFormatter   *formatter.BIND9Formatter
	ctFormatter    *formatter.AWSCloudTrailFormatter
	entraFormatter *formatter.EntraIDFormatter
	orchestrator   *scenario.Orchestrator
}

// NewEngine initializes the core generation engine.
func NewEngine(cfg config.SimulationConfig, fm *fleet.FleetManager, sensor QueueSensor) *Engine {
	schedCfg := SchedulerConfig{
		TargetEPS:       cfg.TargetEPS,
		DurationSeconds: cfg.DurationSeconds,
	}

	fmts := scenario.NewFormatters()
	orchCfg := scenario.OrchestratorConfig{
		SuspiciousRatio: cfg.SuspiciousRatio,
	}
	orch := scenario.NewOrchestrator(orchCfg, fm, fmts)

	return &Engine{
		cfg:            cfg,
		fleetMgr:       fm,
		scheduler:      NewScheduler(schedCfg, sensor),
		outChan:        make(chan *ByteBuffer, 50000), // Bounded buffer channel
		rng:            rand.New(rand.NewSource(cfg.RandomSeed)),
		winFormatter:   fmts.Windows,
		linuxFormatter: fmts.Linux,
		paFormatter:    fmts.PaloAlto,
		dnsFormatter:   fmts.BIND9,
		ctFormatter:    fmts.CloudTrail,
		entraFormatter: fmts.EntraID,
		orchestrator:   orch,
	}
}

// OutputChannel returns the channel streaming generated raw byte buffers.
func (e *Engine) OutputChannel() <-chan *ByteBuffer {
	return e.outChan
}

// Scheduler returns the underlying rate scheduler.
func (e *Engine) Scheduler() *Scheduler {
	return e.scheduler
}

// Orchestrator returns the attack scenario orchestrator.
func (e *Engine) Orchestrator() *scenario.Orchestrator {
	return e.orchestrator
}

// Run executes the generation engine until the context is canceled or duration elapses.
func (e *Engine) Run(ctx context.Context) {
	defer close(e.outChan)

	numWorkers := e.scheduler.cfg.WorkerCount
	if numWorkers <= 0 {
		numWorkers = 1
	}
	workerRNGs := make([]*rand.Rand, numWorkers)
	for i := 0; i < numWorkers; i++ {
		workerRNGs[i] = rand.New(rand.NewSource(e.cfg.RandomSeed + int64(i)*1000 + 1))
	}

	e.scheduler.Start(ctx, func(workerID int, quota int) {
		rng := workerRNGs[workerID%numWorkers]
		for i := 0; i < quota; i++ {
			buf := GetBuffer()
			now := time.Now().UTC()

			if e.orchestrator.ShouldEmitSuspicious(rng) {
				e.orchestrator.StepSuspicious(buf, now, uint64(workerID*100000+i), rng)
			} else {
				ep := e.fleetMgr.SampleWeighted()
				if ep == nil {
					buf.Release()
					continue
				}
				e.SynthesizeBaselineEventWithRNG(ep, buf, rng)
			}

			select {
			case <-ctx.Done():
				buf.Release()
				return
			case e.outChan <- buf:
			}
		}
	})
}

// SynthesizeBaselineEvent synthesizes a fast, realistic baseline enterprise log into the buffer using the default RNG.
func (e *Engine) SynthesizeBaselineEvent(ep *fleet.Endpoint, buf *ByteBuffer) {
	e.SynthesizeBaselineEventWithRNG(ep, buf, e.rng)
}

// SynthesizeBaselineEventWithRNG synthesizes a fast, realistic baseline enterprise log with a thread-safe RNG.
func (e *Engine) SynthesizeBaselineEventWithRNG(ep *fleet.Endpoint, buf *ByteBuffer, rng *rand.Rand) {
	now := time.Now().UTC()

	switch ep.Role {
	case fleet.RoleWorkstation, fleet.RoleDomainController:
		// Dynamic Windows Security XML (4688, 4624, 4625, 4720)
		e.winFormatter.FormatRandomEvent(buf, ep, uint64(ep.NextPID()*100), now, rng)

	case fleet.RoleLinuxServer:
		// Linux authentication & administration telemetry (sshd success/failure, sudo, systemd)
		e.linuxFormatter.FormatRandomLinuxEvent(buf, ep, formatter.SyslogFormatRFC3164, now, rng)

	case fleet.RoleFirewall:
		// Authentic PAN-OS 10.x/11.x Traffic Allow/Drop & Threat CSV
		e.paFormatter.FormatRandomFirewallEvent(buf, ep, uint64(ep.NextPID()*50), now, rng)

	case fleet.RoleCloudAccount:
		// Authentic AWS CloudTrail JSON and Microsoft Entra ID Sign-in logs
		if rng.Intn(2) == 0 {
			e.ctFormatter.FormatRandomCloudTrailEvent(buf, ep, now, rng)
		} else {
			e.entraFormatter.FormatRandomEntraIDEvent(buf, ep, now, rng)
		}

	default:
		// Enterprise DNS (BIND9) standard recursive query lookups and NXDOMAIN responses
		e.dnsFormatter.FormatRandomDNSQuery(buf, ep, now, rng)
	}
}

// QueueDepthPercent implementation for nil checks.
func (e *Engine) QueueDepthPercent() float64 {
	if cap(e.outChan) == 0 {
		return 0
	}
	return float64(len(e.outChan)) / float64(cap(e.outChan))
}

// Stats returns generation runtime stats.
func (e *Engine) Stats() string {
	return fmt.Sprintf("Generated: %d | Current EPS: %d",
		e.scheduler.TotalGenerated(), e.scheduler.CurrentEPS())
}

