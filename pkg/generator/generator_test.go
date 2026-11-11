package generator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

func TestByteBufferOperations(t *testing.T) {
	buf := GetBuffer()
	defer buf.Release()

	buf.AppendString("USER=")
	buf.AppendString("alice")
	buf.AppendString(" PID=")
	buf.AppendInt(1337)
	buf.AppendString(" LOGON=")
	buf.AppendHex(0x1A2B)
	buf.AppendByte(' ')

	fixedTime := time.Date(2026, 11, 12, 4, 15, 30, 0, time.UTC)
	buf.AppendTimeISO8601(fixedTime)

	expected := "USER=alice PID=1337 LOGON=0x1a2b 2026-11-12T04:15:30.000000Z"
	if !strings.HasPrefix(buf.String(), expected) {
		t.Errorf("unexpected buffer content: got %q, expected prefix %q", buf.String(), expected)
	}

	if buf.Len() != len(buf.String()) {
		t.Errorf("buffer Len mismatch: %d vs %d", buf.Len(), len(buf.String()))
	}
}

func TestByteBufferZeroAllocations(t *testing.T) {
	buf := GetBuffer()
	defer buf.Release()

	now := time.Now().UTC()
	allocs := testing.AllocsPerRun(100, func() {
		buf.Reset()
		buf.AppendString("<Event><System><EventID>")
		buf.AppendInt(4624)
		buf.AppendString("</EventID><TimeCreated SystemTime=\"")
		buf.AppendTimeISO8601(now)
		buf.AppendString("\"/></System></Event>\n")
	})

	if allocs > 0 {
		t.Errorf("expected 0 allocations per run, got %f", allocs)
	}
}

func TestSchedulerRatePacing(t *testing.T) {
	targetEPS := 2000
	schedCfg := SchedulerConfig{
		TargetEPS:       targetEPS,
		DurationSeconds: 1,
		WorkerCount:     4,
	}

	scheduler := NewScheduler(schedCfg, nil)
	ctx := context.Background()

	var counter int64
	scheduler.Start(ctx, func(workerID int, quota int) {
		for i := 0; i < quota; i++ {
			counter++
		}
	})

	total := scheduler.TotalGenerated()
	// Allow +/- 10% tolerance for 1-second burst interval
	minExpected := uint64(float64(targetEPS) * 0.90)
	maxExpected := uint64(float64(targetEPS) * 1.10)

	if total < minExpected || total > maxExpected {
		t.Errorf("rate pacing drift: generated %d events, expected range [%d, %d]", total, minExpected, maxExpected)
	}
}

func BenchmarkByteBufferAppend(b *testing.B) {
	buf := GetBuffer()
	defer buf.Release()
	now := time.Now().UTC()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		buf.AppendString("<86>")
		buf.AppendTimeSyslog(now)
		buf.AppendString(" srv-app01 sshd[1420]: Accepted publickey for user admin from 10.100.0.12 port 54822 ssh2\n")
	}
}

func BenchmarkEngineThroughput100kEPS(b *testing.B) {
	cfg := config.SimulationConfig{
		TargetEPS:       100000,
		DurationSeconds: 1,
		RandomSeed:      42,
	}
	fleetCfg := config.FleetConfig{
		TotalEndpoints: 100,
		Distribution: config.EndpointDistribution{
			WindowsWorkstations: 60,
			LinuxServers:        20,
			Firewalls:           10,
			DNSServers:          5,
			WebServers:          5,
		},
	}

	fm, _ := fleet.NewFleetManager(42)
	_ = fm.GenerateFleet(fleetCfg)

	engine := NewEngine(cfg, fm, nil)
	ep := fm.SampleRandom()
	buf := GetBuffer()
	defer buf.Release()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		engine.SynthesizeBaselineEvent(ep, buf)
	}
}
