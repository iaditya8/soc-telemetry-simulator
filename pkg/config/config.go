package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete runtime configuration for the SOC Telemetry Simulator.
type Config struct {
	Simulation  SimulationConfig  `yaml:"simulation" json:"simulation"`
	Fleet       FleetConfig       `yaml:"fleet" json:"fleet"`
	Destination DestinationConfig `yaml:"destination" json:"destination"`
	Server      ServerConfig      `yaml:"server" json:"server"`
	Ledger      LedgerConfig      `yaml:"ledger" json:"ledger"`
}

// SimulationConfig controls throughput, ratios, and run duration.
type SimulationConfig struct {
	TargetEPS       int      `yaml:"target_eps" json:"target_eps"`             // Target events per second (e.g., 1000 to 100000+)
	DurationSeconds int      `yaml:"duration_seconds" json:"duration_seconds"` // Run duration in seconds (0 = continuous)
	NormalRatio     float64  `yaml:"normal_ratio" json:"normal_ratio"`         // Proportion of normal events (0.0 to 1.0, e.g., 0.95)
	SuspiciousRatio float64  `yaml:"suspicious_ratio" json:"suspicious_ratio"` // Proportion of suspicious events (0.0 to 1.0, e.g., 0.05)
	RandomSeed      int64    `yaml:"random_seed" json:"random_seed"`           // Seed for deterministic generation (0 = random)
	ActiveScenarios []string `yaml:"active_scenarios" json:"active_scenarios"` // Enabled MITRE ATT&CK scenario IDs
}

// FleetConfig controls the virtual fleet size and composition.
type FleetConfig struct {
	TotalEndpoints int                  `yaml:"total_endpoints" json:"total_endpoints"` // Total logical endpoints
	Distribution   EndpointDistribution `yaml:"distribution" json:"distribution"`       // Distribution of roles
}

// EndpointDistribution defines role percentages across the fleet.
type EndpointDistribution struct {
	WindowsWorkstations int `yaml:"windows_workstations" json:"windows_workstations"` // Percentage (e.g. 60)
	LinuxServers        int `yaml:"linux_servers" json:"linux_servers"`               // Percentage (e.g. 20)
	Firewalls           int `yaml:"firewalls" json:"firewalls"`                       // Percentage (e.g. 10)
	DNSServers          int `yaml:"dns_servers" json:"dns_servers"`                   // Percentage (e.g. 5)
	WebServers          int `yaml:"web_servers" json:"web_servers"`                   // Percentage (e.g. 5)
}

// DestinationConfig defines the SIEM transport parameters (Spectra/Syslog/HEC).
type DestinationConfig struct {
	Transport           string `yaml:"transport" json:"transport"`                         // "tcp", "tls", "hec", "file", "mock"
	Host                string `yaml:"host" json:"host"`                                   // Target host or IP
	Port                int    `yaml:"port" json:"port"`                                   // Target port (e.g., 514, 8088)
	Path                string `yaml:"path" json:"path"`                                   // HTTP path (e.g., "/services/collector/raw")
	AuthToken           string `yaml:"auth_token" json:"auth_token"`                       // Bearer / API token (redacted in reports)
	TLSVerify           bool   `yaml:"tls_verify" json:"tls_verify"`                       // Verify TLS certificates
	BatchSizeEvents     int    `yaml:"batch_size_events" json:"batch_size_events"`         // Batch flush trigger by count (e.g., 1000 - 5000)
	BatchFlushTimeoutMs int    `yaml:"batch_flush_timeout_ms" json:"batch_flush_timeout_ms"` // Batch flush trigger by latency (e.g., 100)
	QueueCapacity       int    `yaml:"queue_capacity" json:"queue_capacity"`               // Bounded ring buffer size (default 50,000)
	OverflowPolicy      string `yaml:"overflow_policy" json:"overflow_policy"`             // "pause" (lossless) or "drop" (stress)
}

// ServerConfig controls the embedded dashboard and API server.
type ServerConfig struct {
	BindAddress string `yaml:"bind_address" json:"bind_address"` // Local address, strictly 127.0.0.1
	Port        int    `yaml:"port" json:"port"`                 // Web dashboard port (default 8080)
}

// LedgerConfig controls audit retention and report generation.
type LedgerConfig struct {
	EnableSQLite    bool   `yaml:"enable_sqlite" json:"enable_sqlite"`         // Persist run history to SQLite
	DatabasePath    string `yaml:"database_path" json:"database_path"`         // Path to SQLite db file
	ReportOutputDir string `yaml:"report_output_dir" json:"report_output_dir"` // Output dir for HTML/JSON/CSV
}

// DefaultConfig returns safe, pre-validated defaults matching specifications.
func DefaultConfig() *Config {
	return &Config{
		Simulation: SimulationConfig{
			TargetEPS:       1000,
			DurationSeconds: 60,
			NormalRatio:     0.95,
			SuspiciousRatio: 0.05,
			RandomSeed:      42,
			ActiveScenarios: []string{"T1110.001", "T1046", "T1071.004"},
		},
		Fleet: FleetConfig{
			TotalEndpoints: 100,
			Distribution: EndpointDistribution{
				WindowsWorkstations: 60,
				LinuxServers:        20,
				Firewalls:           10,
				DNSServers:          5,
				WebServers:          5,
			},
		},
		Destination: DestinationConfig{
			Transport:           "tcp",
			Host:                "127.0.0.1",
			Port:                514,
			Path:                "/services/collector/raw",
			AuthToken:           "",
			TLSVerify:           false,
			BatchSizeEvents:     2000,
			BatchFlushTimeoutMs: 100,
			QueueCapacity:       50000,
			OverflowPolicy:      "pause",
		},
		Server: ServerConfig{
			BindAddress: "127.0.0.1",
			Port:        8080,
		},
		Ledger: LedgerConfig{
			EnableSQLite:    true,
			DatabasePath:    "soc_simulator.db",
			ReportOutputDir: "reports/output",
		},
	}
}

// LoadConfig reads a YAML configuration file or returns defaults if path is empty.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks internal consistency and safety constraints.
func (c *Config) Validate() error {
	if c.Simulation.TargetEPS <= 0 {
		return fmt.Errorf("target_eps must be greater than 0, got %d", c.Simulation.TargetEPS)
	}
	if c.Simulation.NormalRatio < 0 || c.Simulation.NormalRatio > 1.0 {
		return fmt.Errorf("normal_ratio must be between 0.0 and 1.0, got %f", c.Simulation.NormalRatio)
	}
	if c.Simulation.SuspiciousRatio < 0 || c.Simulation.SuspiciousRatio > 1.0 {
		return fmt.Errorf("suspicious_ratio must be between 0.0 and 1.0, got %f", c.Simulation.SuspiciousRatio)
	}
	// Tolerate minor floating point rounding
	totalRatio := c.Simulation.NormalRatio + c.Simulation.SuspiciousRatio
	if totalRatio < 0.999 || totalRatio > 1.001 {
		return fmt.Errorf("normal_ratio + suspicious_ratio must equal 1.0, got %f", totalRatio)
	}

	if c.Fleet.TotalEndpoints <= 0 {
		return fmt.Errorf("total_endpoints must be > 0, got %d", c.Fleet.TotalEndpoints)
	}

	dist := c.Fleet.Distribution
	totalDist := dist.WindowsWorkstations + dist.LinuxServers + dist.Firewalls + dist.DNSServers + dist.WebServers
	if totalDist != 100 {
		return fmt.Errorf("endpoint distribution percentages must sum to 100, got %d", totalDist)
	}

	if c.Destination.QueueCapacity <= 0 {
		c.Destination.QueueCapacity = 50000
	}
	if c.Destination.BatchSizeEvents <= 0 {
		c.Destination.BatchSizeEvents = 1000
	}

	return nil
}

// BatchDuration converts milliseconds to time.Duration.
func (d *DestinationConfig) BatchDuration() time.Duration {
	if d.BatchFlushTimeoutMs <= 0 {
		return 100 * time.Millisecond
	}
	return time.Duration(d.BatchFlushTimeoutMs) * time.Millisecond
}

