package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

const (
	Version = "1.0.0"
	Banner  = `
========================================================================
   ____ ____   ____   _____     _                      _                
  / ___/ _  \ / ___| |_   _|___| | ___ _ __ ___   ___ | |_ _ __ _   _  
  \___ \ | | | |       | |/ _ \ |/ _ \ '_ ` + "`" + ` _ \ / _ \| __| '__| | | | 
   ___) | |_| | |___   | |  __/ |  __/ | | | | |  __/| |_| |  | |_| | 
  |____/\____/ \____|  |_|\___|_|\___|_| |_| |_|\___| \__|_|   \__, | 
               S I M U L A T O R                               |___/  
========================================================================
  High-Volume Enterprise Raw Log Generator & SIEM Ingestion Benchmark
========================================================================
`
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to YAML configuration file")
	targetEPS := flag.Int("eps", 0, "Override target EPS (events/sec)")
	durationSec := flag.Int("duration", -1, "Override duration in seconds (0 = continuous)")
	showVersion := flag.Bool("version", false, "Display software version and exit")
	mode := flag.String("mode", "run", "Execution mode: run, server, receiver")

	flag.Parse()

	if *showVersion {
		fmt.Printf("SOC Telemetry Simulator v%s\n", Version)
		os.Exit(0)
	}

	fmt.Print(Banner)
	fmt.Printf(" [System] Initializing runtime (Version %s)...\n", Version)

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, " [Error] Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Apply CLI overrides if specified
	if *targetEPS > 0 {
		cfg.Simulation.TargetEPS = *targetEPS
	}
	if *durationSec >= 0 {
		cfg.Simulation.DurationSeconds = *durationSec
	}

	fmt.Printf(" [Config] Loaded config from %s\n", *configPath)
	fmt.Printf(" [Config] Target Throughput: %d EPS | Duration: %d seconds\n",
		cfg.Simulation.TargetEPS, cfg.Simulation.DurationSeconds)
	fmt.Printf(" [Config] Virtual Fleet: %d logical endpoints\n", cfg.Fleet.TotalEndpoints)

	// Initialize Fleet Manager
	fleetMgr, err := fleet.NewFleetManager(cfg.Simulation.RandomSeed)
	if err != nil {
		fmt.Fprintf(os.Stderr, " [Error] Failed to initialize fleet manager: %v\n", err)
		os.Exit(1)
	}
	if err := fleetMgr.GenerateFleet(cfg.Fleet); err != nil {
		fmt.Fprintf(os.Stderr, " [Error] Failed to generate virtual fleet: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(" [Fleet] Successfully synthesized %d logical endpoints across 5 isolated subnets.\n",
		fleetMgr.TotalCount())
	fmt.Printf(" [Config] Destination: %s (%s:%d)\n",
		cfg.Destination.Transport, cfg.Destination.Host, cfg.Destination.Port)
	fmt.Printf(" [Config] Activity Mix: %.0f%% Normal / %.0f%% Suspicious\n",
		cfg.Simulation.NormalRatio*100, cfg.Simulation.SuspiciousRatio*100)

	switch *mode {
	case "run":
		fmt.Println(" [Engine] Mode: Run - Ready for simulation engine execution.")
	case "server":
		fmt.Printf(" [Server] Mode: Web Dashboard Server on %s:%d\n", cfg.Server.BindAddress, cfg.Server.Port)
	case "receiver":
		fmt.Printf(" [Receiver] Mode: Mock Spectra Receiver listening on port %d\n", cfg.Destination.Port)
	default:
		fmt.Fprintf(os.Stderr, " [Error] Unknown mode %q (expected: run, server, receiver)\n", *mode)
		os.Exit(1)
	}
}

