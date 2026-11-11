package generator

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/formatter"
)

// Engine orchestrates high-volume log generation across fleet endpoints.
type Engine struct {
	cfg          config.SimulationConfig
	fleetMgr     *fleet.FleetManager
	scheduler    *Scheduler
	outChan      chan *ByteBuffer
	rng          *rand.Rand
	winFormatter *formatter.WindowsXMLFormatter
}

// NewEngine initializes the core generation engine.
func NewEngine(cfg config.SimulationConfig, fm *fleet.FleetManager, sensor QueueSensor) *Engine {
	schedCfg := SchedulerConfig{
		TargetEPS:       cfg.TargetEPS,
		DurationSeconds: cfg.DurationSeconds,
	}

	return &Engine{
		cfg:          cfg,
		fleetMgr:     fm,
		scheduler:    NewScheduler(schedCfg, sensor),
		outChan:      make(chan *ByteBuffer, 50000), // Bounded buffer channel
		rng:          rand.New(rand.NewSource(cfg.RandomSeed)),
		winFormatter: formatter.NewWindowsXMLFormatter(),
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
			ep := e.fleetMgr.SampleWeighted()
			if ep == nil {
				continue
			}

			buf := GetBuffer()
			e.SynthesizeBaselineEventWithRNG(ep, buf, rng)

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
		// Linux sshd accepted publickey (RFC 3164)
		buf.AppendString("<86>")
		buf.AppendTimeSyslog(now)
		buf.AppendByte(' ')
		buf.AppendString(ep.Hostname)
		buf.AppendString(" sshd[")
		buf.AppendUint(uint64(ep.NextPID()))
		buf.AppendString("]: Accepted publickey for ")
		buf.AppendString(ep.PrimaryUser().Username)
		buf.AppendString(" from ")
		buf.AppendString(ep.IP.String())
		buf.AppendString(" port 54822 ssh2\n")

	case fleet.RoleFirewall:
		// Palo Alto Traffic Allow CSV
		buf.AppendString("1,")
		buf.Append(now.AppendFormat(nil, "2006/01/02 15:04:05"))
		buf.AppendString(",001801004215,TRAFFIC,allow,2304,")
		buf.Append(now.AppendFormat(nil, "2006/01/02 15:04:05"))
		buf.AppendByte(',')
		buf.AppendString(ep.IP.String())
		buf.AppendString(",172.16.10.15,0.0.0.0,0.0.0.0,Allow-Web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,Forward-All,")
		buf.Append(now.AppendFormat(nil, "2006/01/02 15:04:05"))
		buf.AppendString(",0,1,54120,443,0,0,0x0,tcp,allow,1420,0,0,12,")
		buf.Append(now.AppendFormat(nil, "2006/01/02 15:04:05"))
		buf.AppendString(",0,any,0,1082910,0x0,US,0,1,0,from-policy,0,0,0,0,,")
		buf.AppendString(ep.Hostname)
		buf.AppendString(",from-policy\n")

	default:
		// Generic BIND9 DNS query
		buf.Append(now.AppendFormat(nil, "02-Jan-2006 15:04:05.000"))
		buf.AppendString(" client @0x7f481014a000 ")
		buf.AppendString(ep.IP.String())
		buf.AppendString("#51920 (portal.corp.local): query: portal.corp.local IN A + (10.200.10.1)\n")
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

