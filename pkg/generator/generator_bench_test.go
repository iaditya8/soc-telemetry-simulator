package generator

import (
	"runtime"
	"testing"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

// BenchmarkMemoryGeneration100kEPS generates raw enterprise telemetry across 100 logical
// endpoints, verifying 100,000+ EPS capability with near-zero allocations.
func BenchmarkMemoryGeneration100kEPS(b *testing.B) {
	cfg := config.SimulationConfig{
		TargetEPS:       100000,
		DurationSeconds: 1,
		NormalRatio:     0.95,
		SuspiciousRatio: 0.05,
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

	fm, err := fleet.NewFleetManager(42)
	if err != nil {
		b.Fatalf("failed to initialize fleet manager: %v", err)
	}
	if err := fm.GenerateFleet(fleetCfg); err != nil {
		b.Fatalf("failed to generate fleet: %v", err)
	}

	engine := NewEngine(cfg, fm, nil)
	buf := GetBuffer()
	defer buf.Release()

	endpoints := fm.Endpoints()
	epCount := len(endpoints)
	if epCount == 0 {
		b.Fatal("fleet empty")
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		ep := endpoints[i%epCount]
		engine.SynthesizeBaselineEvent(ep, buf)
	}
}

// TestMemoryStress500MBCap synthesizes 1,000,000 events continuously while asserting
// that process heap memory stays strictly below the 500 MB guardrail.
func TestMemoryStress500MBCap(t *testing.T) {
	cfg := config.SimulationConfig{
		TargetEPS:       100000,
		DurationSeconds: 10,
		NormalRatio:     0.95,
		SuspiciousRatio: 0.05,
		RandomSeed:      42,
	}
	fleetCfg := config.FleetConfig{
		TotalEndpoints: 250,
		Distribution: config.EndpointDistribution{
			WindowsWorkstations: 60,
			LinuxServers:        20,
			Firewalls:           10,
			DNSServers:          5,
			WebServers:          5,
		},
	}

	fm, err := fleet.NewFleetManager(42)
	if err != nil {
		t.Fatalf("failed to initialize fleet manager: %v", err)
	}
	if err := fm.GenerateFleet(fleetCfg); err != nil {
		t.Fatalf("failed to generate fleet: %v", err)
	}

	engine := NewEngine(cfg, fm, nil)
	endpoints := fm.Endpoints()
	epCount := len(endpoints)

	buf := GetBuffer()
	defer buf.Release()

	// Synthesize 1,000,000 events
	const totalEvents = 1_000_000
	for i := 0; i < totalEvents; i++ {
		buf.Reset()
		ep := endpoints[i%epCount]
		engine.SynthesizeBaselineEvent(ep, buf)

		if i > 0 && i%200_000 == 0 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			allocMB := float64(m.Alloc) / (1024 * 1024)
			if allocMB > 500.0 {
				t.Fatalf("memory stress breach: allocated %.2f MB exceeds 500 MB ceiling at iteration %d", allocMB, i)
			}
		}
	}

	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)
	finalAllocMB := float64(finalMem.Alloc) / (1024 * 1024)
	if finalAllocMB > 500.0 {
		t.Fatalf("final memory footprint %.2f MB exceeds 500 MB ceiling", finalAllocMB)
	}
	t.Logf("1,000,000 events synthesized. Final Alloc: %.2f MB, Sys: %.2f MB, NumGC: %d",
		finalAllocMB, float64(finalMem.Sys)/(1024*1024), finalMem.NumGC)
}
