package fleet

import (
	"testing"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
)

func TestFleetGenerationUniqueness(t *testing.T) {
	fm, err := NewFleetManager(42)
	if err != nil {
		t.Fatalf("NewFleetManager failed: %v", err)
	}

	cfg := config.FleetConfig{
		TotalEndpoints: 150,
		Distribution: config.EndpointDistribution{
			WindowsWorkstations: 60,
			LinuxServers:        20,
			Firewalls:           10,
			DNSServers:          5,
			WebServers:          5,
		},
	}

	if err := fm.GenerateFleet(cfg); err != nil {
		t.Fatalf("GenerateFleet failed: %v", err)
	}

	if fm.TotalCount() != 150 {
		t.Errorf("expected 150 endpoints, got %d", fm.TotalCount())
	}

	// Verify 100% IP and Hostname uniqueness
	seenIPs := make(map[string]string)
	seenHostnames := make(map[string]string)

	for _, ep := range fm.Endpoints() {
		ipStr := ep.IP.String()
		if existingID, exists := seenIPs[ipStr]; exists {
			t.Fatalf("IP collision detected: %s shared by %s and %s", ipStr, existingID, ep.ID)
		}
		seenIPs[ipStr] = ep.ID

		if existingID, exists := seenHostnames[ep.Hostname]; exists {
			t.Fatalf("Hostname collision detected: %s shared by %s and %s", ep.Hostname, existingID, ep.ID)
		}
		seenHostnames[ep.Hostname] = ep.ID
	}
}

func TestFleetDeterministicSeed(t *testing.T) {
	cfg := config.FleetConfig{
		TotalEndpoints: 50,
		Distribution: config.EndpointDistribution{
			WindowsWorkstations: 60,
			LinuxServers:        20,
			Firewalls:           10,
			DNSServers:          5,
			WebServers:          5,
		},
	}

	fm1, _ := NewFleetManager(9999)
	if err := fm1.GenerateFleet(cfg); err != nil {
		t.Fatalf("fm1 GenerateFleet failed: %v", err)
	}

	fm2, _ := NewFleetManager(9999)
	if err := fm2.GenerateFleet(cfg); err != nil {
		t.Fatalf("fm2 GenerateFleet failed: %v", err)
	}

	eps1 := fm1.Endpoints()
	eps2 := fm2.Endpoints()

	if len(eps1) != len(eps2) {
		t.Fatalf("endpoint count mismatch: %d vs %d", len(eps1), len(eps2))
	}

	for i := range eps1 {
		if eps1[i].ID != eps2[i].ID {
			t.Errorf("endpoint %d ID mismatch: %s vs %s", i, eps1[i].ID, eps2[i].ID)
		}
		if eps1[i].IP.String() != eps2[i].IP.String() {
			t.Errorf("endpoint %d IP mismatch: %s vs %s", i, eps1[i].IP, eps2[i].IP)
		}
		if eps1[i].Hostname != eps2[i].Hostname {
			t.Errorf("endpoint %d Hostname mismatch: %s vs %s", i, eps1[i].Hostname, eps2[i].Hostname)
		}
	}
}

func TestRoleSampling(t *testing.T) {
	fm, _ := NewFleetManager(1234)
	cfg := config.FleetConfig{
		TotalEndpoints: 100,
		Distribution: config.EndpointDistribution{
			WindowsWorkstations: 60,
			LinuxServers:        20,
			Firewalls:           10,
			DNSServers:          5,
			WebServers:          5,
		},
	}
	_ = fm.GenerateFleet(cfg)

	wks, err := fm.SampleByRole(RoleWorkstation)
	if err != nil || wks.Role != RoleWorkstation {
		t.Errorf("expected workstation endpoint, got %v (err: %v)", wks, err)
	}

	fw, err := fm.SampleByRole(RoleFirewall)
	if err != nil || fw.Role != RoleFirewall {
		t.Errorf("expected firewall endpoint, got %v (err: %v)", fw, err)
	}

	randomEP := fm.SampleRandom()
	if randomEP == nil {
		t.Errorf("SampleRandom returned nil")
	}

	weightedEP := fm.SampleWeighted()
	if weightedEP == nil {
		t.Errorf("SampleWeighted returned nil")
	}
}

func TestSampleWeightedDistribution(t *testing.T) {
	fm, err := NewFleetManager(42)
	if err != nil {
		t.Fatalf("failed to create fleet manager: %v", err)
	}

	ep1 := &Endpoint{ID: "EP-A", Role: RoleWorkstation, Weight: 80.0}
	ep2 := &Endpoint{ID: "EP-B", Role: RoleLinuxServer, Weight: 20.0}
	ep3 := &Endpoint{ID: "EP-C", Role: RoleFirewall, Weight: 0.0}

	fm.endpoints = []*Endpoint{ep1, ep2, ep3}

	counts := make(map[string]int)
	const samples = 1000
	for i := 0; i < samples; i++ {
		ep := fm.SampleWeighted()
		if ep == nil {
			t.Fatalf("SampleWeighted returned nil")
		}
		counts[ep.ID]++
	}

	if counts["EP-C"] != 0 {
		t.Errorf("zero-weight endpoint EP-C was selected %d times, expected 0", counts["EP-C"])
	}
	if counts["EP-A"] < 650 || counts["EP-A"] > 950 {
		t.Errorf("expected EP-A to receive ~80%% selections (got %d / %d)", counts["EP-A"], samples)
	}
	if counts["EP-B"] < 50 || counts["EP-B"] > 350 {
		t.Errorf("expected EP-B to receive ~20%% selections (got %d / %d)", counts["EP-B"], samples)
	}
}

func TestGenerateFleetNegativePreservesFleet(t *testing.T) {
	fm, _ := NewFleetManager(1)
	cfg := config.FleetConfig{
		TotalEndpoints: 10,
		Distribution: config.EndpointDistribution{
			WindowsWorkstations: 100,
		},
	}
	if err := fm.GenerateFleet(cfg); err != nil {
		t.Fatalf("initial generation failed: %v", err)
	}
	if len(fm.Endpoints()) != 10 {
		t.Fatalf("expected 10 endpoints, got %d", len(fm.Endpoints()))
	}

	invalidCfg := config.FleetConfig{
		TotalEndpoints: 10,
		Distribution: config.EndpointDistribution{
			WindowsWorkstations: -10,
		},
	}
	err := fm.GenerateFleet(invalidCfg)
	if err == nil {
		t.Fatalf("expected error for negative role percentage, got nil")
	}
	if len(fm.Endpoints()) != 10 {
		t.Errorf("fleet was wiped upon invalid config: expected 10 endpoints, got %d", len(fm.Endpoints()))
	}
}

func TestPIDProgression(t *testing.T) {
	ep := &Endpoint{}
	pid1 := ep.NextPID()
	pid2 := ep.NextPID()

	if pid1 < 1024 {
		t.Errorf("expected initial PID >= 1024, got %d", pid1)
	}
	if pid2 <= pid1 {
		t.Errorf("expected PID progression, got pid1=%d, pid2=%d", pid1, pid2)
	}
}

func TestGatewayReservation(t *testing.T) {
	pool, err := NewSubnetPool(ZoneWorkstations, "10.0.0.0/29", "10.0.0.2")
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	// 10.0.0.0/29 usable range: 10.0.0.1 to 10.0.0.6 (6 usable hosts)
	// Gateway is 10.0.0.2
	var allocatedIPs []string
	for i := 0; i < 5; i++ {
		ip, err := pool.NextIP()
		if err != nil {
			t.Fatalf("allocation %d failed: %v", i, err)
		}
		if ip.String() == "10.0.0.2" {
			t.Fatalf("gateway 10.0.0.2 was allocated!")
		}
		allocatedIPs = append(allocatedIPs, ip.String())
	}

	// Verify 10.0.0.1 was allocated first
	if allocatedIPs[0] != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1 to be allocated before gateway, got %s", allocatedIPs[0])
	}
}

func BenchmarkFleetGeneration250Endpoints(b *testing.B) {
	cfg := config.FleetConfig{
		TotalEndpoints: 250,
		Distribution: config.EndpointDistribution{
			WindowsWorkstations: 60,
			LinuxServers:        20,
			Firewalls:           10,
			DNSServers:          5,
			WebServers:          5,
		},
	}

	var i int
	for b.Loop() {
		fm, _ := NewFleetManager(int64(i + 1))
		if err := fm.GenerateFleet(cfg); err != nil {
			b.Fatalf("generation failed: %v", err)
		}
		i++
	}
}

