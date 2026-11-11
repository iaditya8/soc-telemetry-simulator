package generator

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

// Engine orchestrates high-volume log generation across fleet endpoints.
type Engine struct {
	cfg       config.SimulationConfig
	fleetMgr  *fleet.FleetManager
	scheduler *Scheduler
	outChan   chan *ByteBuffer
	rng       *rand.Rand
}

// NewEngine initializes the core generation engine.
func NewEngine(cfg config.SimulationConfig, fm *fleet.FleetManager, sensor QueueSensor) *Engine {
	schedCfg := SchedulerConfig{
		TargetEPS:       cfg.TargetEPS,
		DurationSeconds: cfg.DurationSeconds,
	}

	return &Engine{
		cfg:       cfg,
		fleetMgr:  fm,
		scheduler: NewScheduler(schedCfg, sensor),
		outChan:   make(chan *ByteBuffer, 50000), // Bounded buffer channel
		rng:       rand.New(rand.NewSource(cfg.RandomSeed)),
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

	e.scheduler.Start(ctx, func(workerID int, quota int) {
		for i := 0; i < quota; i++ {
			ep := e.fleetMgr.SampleWeighted()
			if ep == nil {
				continue
			}

			buf := GetBuffer()
			e.SynthesizeBaselineEvent(ep, buf)

			select {
			case <-ctx.Done():
				buf.Release()
				return
			case e.outChan <- buf:
			}
		}
	})
}

// SynthesizeBaselineEvent synthesizes a fast, realistic baseline enterprise log into the buffer.
func (e *Engine) SynthesizeBaselineEvent(ep *fleet.Endpoint, buf *ByteBuffer) {
	now := time.Now().UTC()

	switch ep.Role {
	case fleet.RoleWorkstation, fleet.RoleDomainController:
		// Windows Security Event XML 4624 (Logon Success)
		user := ep.PrimaryUser()
		buf.AppendString("<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-A5BA-3E3B0328C30D}\"/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"")
		buf.AppendTimeISO8601(now)
		buf.AppendString("\"/><EventRecordID>")
		buf.AppendUint(uint64(ep.NextPID() * 100))
		buf.AppendString("</EventRecordID><Execution ProcessID=\"688\" ThreadID=\"1920\"/><Channel>Security</Channel><Computer>")
		buf.AppendString(ep.Hostname)
		buf.AppendString("</Computer><Security/></System><EventData><Data Name=\"TargetUserSid\">")
		buf.AppendString(user.UserSID)
		buf.AppendString("</Data><Data Name=\"TargetUserName\">")
		buf.AppendString(user.Username)
		buf.AppendString("</Data><Data Name=\"TargetDomainName\">")
		buf.AppendString(user.Domain)
		buf.AppendString("</Data><Data Name=\"TargetLogonId\">")
		buf.AppendString(ep.NextLogonHex())
		buf.AppendString("</Data><Data Name=\"LogonType\">2</Data><Data Name=\"IpAddress\">")
		buf.AppendString(ep.IP.String())
		buf.AppendString("</Data><Data Name=\"IpPort\">")
		buf.AppendInt(int64(49152 + (ep.NextPID() % 1000)))
		buf.AppendString("</Data></EventData></Event>\n")

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

