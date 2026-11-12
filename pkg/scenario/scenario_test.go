package scenario

import (
	"math"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

func setupTestFleet() (*fleet.FleetManager, *Formatters) {
	fm, _ := fleet.NewFleetManager(42)
	_ = fm.GenerateFleet(config.FleetConfig{
		TotalEndpoints: 100,
		Distribution: config.EndpointDistribution{
			WindowsWorkstations: 60,
			LinuxServers:        20,
			Firewalls:           10,
			DNSServers:          5,
			WebServers:          5,
		},
	})
	return fm, NewFormatters()
}

func TestBruteForceScenarioWindows(t *testing.T) {
	_, fmts := setupTestFleet()
	wks := &fleet.Endpoint{
		ID:       "EP-WIN-01",
		Hostname: "WKS-EXEC-01.corp.local",
		Domain:   "CORP.LOCAL",
		IP:       net.ParseIP("10.100.1.15"),
		IPStr:    "10.100.1.15",
		Role:     fleet.RoleWorkstation,
	}

	sc := NewBruteForceScenario("198.51.100.45", "target.admin", wks, 5, fmts)
	now := time.Now().UTC()
	rng := rand.New(rand.NewSource(123))

	for i := 1; i <= 4; i++ {
		buf := buffer.GetBuffer()
		sc.Step(buf, now, uint64(i), rng)
		line := buf.String()
		buf.Release()

		if !strings.Contains(line, "<EventID>4625</EventID>") {
			t.Fatalf("expected EventID 4625 on attempt %d, got:\n%s", i, line)
		}
		if !strings.Contains(line, "198.51.100.45") {
			t.Fatalf("expected attacker IP on attempt %d", i)
		}
		if !strings.Contains(line, "target.admin") {
			t.Fatalf("expected target user on attempt %d", i)
		}
		if sc.IsCompleted() {
			t.Fatalf("scenario prematurely marked completed at step %d", i)
		}
	}

	// 5th attempt must succeed
	buf := buffer.GetBuffer()
	sc.Step(buf, now, 5, rng)
	line := buf.String()
	buf.Release()

	if !strings.Contains(line, "<EventID>4624</EventID>") {
		t.Fatalf("expected EventID 4624 on 5th attempt, got:\n%s", line)
	}
	if !sc.IsCompleted() {
		t.Fatalf("scenario should be completed after 5 attempts")
	}
}

func TestPortScanScenario(t *testing.T) {
	_, fmts := setupTestFleet()
	fw := &fleet.Endpoint{
		ID:       "EP-FW-01",
		Hostname: "pa-perim-fw01",
		IP:       net.ParseIP("192.168.1.1"),
		IPStr:    "192.168.1.1",
		Role:     fleet.RoleFirewall,
	}
	target := &fleet.Endpoint{
		ID:       "EP-WEB-01",
		Hostname: "portal-web01",
		IP:       net.ParseIP("10.200.10.15"),
		IPStr:    "10.200.10.15",
		Role:     fleet.RoleWebServer,
	}

	sc := NewPortScanScenario("203.0.113.88", target, fw, fmts)
	now := time.Now().UTC()
	rng := rand.New(rand.NewSource(456))

	stepCount := 0
	hasThreatAlert := false

	for !sc.IsCompleted() {
		stepCount++
		buf := buffer.GetBuffer()
		sc.Step(buf, now, uint64(stepCount), rng)
		line := buf.String()
		buf.Release()

		if strings.Contains(line, ",THREAT,") {
			hasThreatAlert = true
		}
	}

	if stepCount != len(sc.ports) {
		t.Fatalf("expected %d steps to complete scan, got %d", len(sc.ports), stepCount)
	}
	if !hasThreatAlert {
		t.Fatalf("expected at least one THREAT alert during port scan")
	}
}

func TestDNSBeaconingScenario(t *testing.T) {
	_, fmts := setupTestFleet()
	src := &fleet.Endpoint{
		ID:    "EP-WIN-01",
		IP:    net.ParseIP("10.100.1.50"),
		IPStr: "10.100.1.50",
	}
	dns := &fleet.Endpoint{
		ID:    "EP-DNS-01",
		IP:    net.ParseIP("10.200.10.1"),
		IPStr: "10.200.10.1",
	}

	sc := NewDNSBeaconingScenario("darkmesh-c2.cc", src, dns, 5, fmts)
	now := time.Now().UTC()
	rng := rand.New(rand.NewSource(789))

	seenDomains := make(map[string]bool)
	for i := 0; i < 5; i++ {
		buf := buffer.GetBuffer()
		sc.Step(buf, now, uint64(i+1), rng)
		line := buf.String()
		buf.Release()

		if !strings.Contains(line, ".darkmesh-c2.cc") {
			t.Fatalf("expected darkmesh-c2.cc in query line:\n%s", line)
		}
		fields := strings.Fields(line)
		domain := fields[4] // e.g. "(<hex>.darkmesh-c2.cc):"
		if seenDomains[domain] {
			t.Fatalf("duplicate high-entropy domain observed: %s", domain)
		}
		seenDomains[domain] = true
	}

	if !sc.IsCompleted() {
		t.Fatalf("DNS beaconing scenario should be completed after 5 queries")
	}
}

func TestObfuscatedPowerShellScenario(t *testing.T) {
	_, fmts := setupTestFleet()
	wks := &fleet.Endpoint{
		ID:       "EP-WIN-01",
		Hostname: "WKS-DEV-01",
		Domain:   "CORP.LOCAL",
		Role:     fleet.RoleWorkstation,
	}

	sc := NewObfuscatedPowerShellScenario(wks, fmts)
	now := time.Now().UTC()
	rng := rand.New(rand.NewSource(999))

	buf := buffer.GetBuffer()
	sc.Step(buf, now, 1, rng)
	line := buf.String()
	buf.Release()

	if !strings.Contains(line, "<EventID>4688</EventID>") {
		t.Fatalf("expected EventID 4688, got:\n%s", line)
	}
	if !strings.Contains(line, "powershell.exe") {
		t.Fatalf("expected powershell.exe in execution line")
	}
	if !sc.IsCompleted() {
		t.Fatalf("expected single-step scenario to complete")
	}
}

func TestOrchestratorRatioBlending(t *testing.T) {
	fm, fmts := setupTestFleet()
	// Configure 5.0% suspicious ratio
	targetRatio := 0.05
	orch := NewOrchestrator(OrchestratorConfig{
		SuspiciousRatio: targetRatio,
	}, fm, fmts)

	rng := rand.New(rand.NewSource(42))
	now := time.Now().UTC()
	const iterations = 50000

	for i := 0; i < iterations; i++ {
		if orch.ShouldEmitSuspicious(rng) {
			buf := buffer.GetBuffer()
			orch.StepSuspicious(buf, now, uint64(i+1), rng)
			if buf.Len() == 0 {
				t.Fatalf("expected non-empty buffer on suspicious step")
			}
			buf.Release()
		}
	}

	tot, _, susp, observedRatio := orch.Stats()
	if tot != iterations {
		t.Fatalf("expected %d total events, got %d", iterations, tot)
	}

	diff := math.Abs(observedRatio - targetRatio)
	if diff > 0.005 { // Within +/- 0.5%
		t.Fatalf("observed ratio %.4f deviated from target %.4f by %.4f (> 0.005 limit)",
			observedRatio, targetRatio, diff)
	}

	if susp == 0 {
		t.Fatalf("no suspicious events emitted")
	}
}

func BenchmarkOrchestratorDecision(b *testing.B) {
	fm, fmts := setupTestFleet()
	orch := NewOrchestrator(OrchestratorConfig{SuspiciousRatio: 0.05}, fm, fmts)
	rng := rand.New(rand.NewSource(1))

	for b.Loop() {
		_ = orch.ShouldEmitSuspicious(rng)
	}
}

func BenchmarkScenarioStep(b *testing.B) {
	_, fmts := setupTestFleet()
	wks := &fleet.Endpoint{
		ID:       "EP-WIN-01",
		Hostname: "WKS-01",
		Domain:   "CORP",
		Role:     fleet.RoleWorkstation,
	}
	sc := NewBruteForceScenario("1.2.3.4", "admin", wks, 100000000, fmts)
	now := time.Now().UTC()
	rng := rand.New(rand.NewSource(1))

	var i uint64
	for b.Loop() {
		buf := buffer.GetBuffer()
		sc.Step(buf, now, i+1, rng)
		buf.Release()
		i++
	}
}
