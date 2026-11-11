package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig() should be valid, got: %v", err)
	}

	if cfg.Simulation.TargetEPS != 1000 {
		t.Errorf("expected default TargetEPS 1000, got %d", cfg.Simulation.TargetEPS)
	}
	if cfg.Fleet.TotalEndpoints != 100 {
		t.Errorf("expected default TotalEndpoints 100, got %d", cfg.Fleet.TotalEndpoints)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name: "Zero EPS",
			modify: func(c *Config) {
				c.Simulation.TargetEPS = 0
			},
			wantErr: true,
		},
		{
			name: "Invalid Ratio Sum",
			modify: func(c *Config) {
				c.Simulation.NormalRatio = 0.5
				c.Simulation.SuspiciousRatio = 0.2
			},
			wantErr: true,
		},
		{
			name: "Invalid Fleet Distribution Sum",
			modify: func(c *Config) {
				c.Fleet.Distribution.WindowsWorkstations = 50
			},
			wantErr: true,
		},
		{
			name: "Zero Endpoints",
			modify: func(c *Config) {
				c.Fleet.TotalEndpoints = 0
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_config.yaml")

	yamlContent := `
simulation:
  target_eps: 5000
  duration_seconds: 120
  normal_ratio: 0.90
  suspicious_ratio: 0.10
  random_seed: 12345
fleet:
  total_endpoints: 50
  distribution:
    windows_workstations: 50
    linux_servers: 30
    firewalls: 10
    dns_servers: 5
    web_servers: 5
destination:
  transport: "tcp"
  host: "10.0.0.1"
  port: 6514
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}

	if cfg.Simulation.TargetEPS != 5000 {
		t.Errorf("expected TargetEPS 5000, got %d", cfg.Simulation.TargetEPS)
	}
	if cfg.Fleet.TotalEndpoints != 50 {
		t.Errorf("expected TotalEndpoints 50, got %d", cfg.Fleet.TotalEndpoints)
	}
	if cfg.Destination.Port != 6514 {
		t.Errorf("expected Port 6514, got %d", cfg.Destination.Port)
	}
}

