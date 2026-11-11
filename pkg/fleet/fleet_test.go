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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fm, _ := NewFleetManager(int64(i + 1))
		if err := fm.GenerateFleet(cfg); err != nil {
			b.Fatalf("generation failed: %v", err)
		}
	}
}
