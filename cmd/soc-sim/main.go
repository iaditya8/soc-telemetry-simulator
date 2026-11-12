package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/generator"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/mockserver"
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
	receiverTCPPort := flag.Int("receiver-tcp-port", 5140, "Mock receiver TCP port (0 to disable)")
	receiverHECPort := flag.Int("receiver-hec-port", 8088, "Mock receiver Splunk HEC port (0 to disable)")
	receiverToken := flag.String("receiver-token", "", "Optional required HEC token for mock receiver")

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
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		fmt.Println(" [Engine] Starting simulation engine...")
		engine := generator.NewEngine(cfg.Simulation, fleetMgr, nil)

		startTime := time.Now()
		go engine.Run(ctx)

		// Consumer worker simulating consumer pipeline
		go func() {
			var eventCount uint64
			for buf := range engine.OutputChannel() {
				eventCount++
				if eventCount == 1 {
					fmt.Printf("\n--- [First Generated Sample Record] ---\n%s---------------------------------------\n\n",
						buf.String())
				}
				buf.Release()
			}
		}()

		// Real-time console status reporter
		reportTicker := time.NewTicker(1 * time.Second)
		defer reportTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				fmt.Printf("\n [Engine] Stopped by operator. Total generated: %d events in %v\n",
					engine.Scheduler().TotalGenerated(), time.Since(startTime).Round(time.Millisecond))
				return

			case <-reportTicker.C:
				sched := engine.Scheduler()
				if !sched.IsRunning() {
					fmt.Printf("\n [Engine] Simulation completed. Total generated: %d events in %v\n",
						sched.TotalGenerated(), time.Since(startTime).Round(time.Millisecond))
					return
				}
				fmt.Printf("\r [Live Monitor] Elapsed: %-6s | Active EPS: %-7d | Cumulative Events: %-9d",
					time.Since(startTime).Round(time.Second), sched.CurrentEPS(), sched.TotalGenerated())
			}
		}
	case "server":
		fmt.Printf(" [Server] Mode: Web Dashboard Server on %s:%d\n", cfg.Server.BindAddress, cfg.Server.Port)
	case "receiver":
		tcpAddr := ""
		if *receiverTCPPort > 0 {
			tcpAddr = fmt.Sprintf(":%d", *receiverTCPPort)
		}
		hecAddr := ""
		if *receiverHECPort > 0 {
			hecAddr = fmt.Sprintf(":%d", *receiverHECPort)
		}

		rcv := mockserver.NewMockReceiver(mockserver.ReceiverConfig{
			TCPAddr:       tcpAddr,
			HECAddr:       hecAddr,
			ExpectedToken: *receiverToken,
		})

		if err := rcv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, " [Error] Failed to start mock receiver: %v\n", err)
			os.Exit(1)
		}
		defer rcv.Close()

		fmt.Printf(" [Receiver] Standalone Mock Spectra SIEM Receiver running!\n")
		if tcpAddr != "" {
			fmt.Printf("   -> TCP/Syslog Endpoint: %s (newline & RFC 5424)\n", rcv.TCPAddr())
		}
		if hecAddr != "" {
			fmt.Printf("   -> Splunk HEC Endpoint: http://%s/services/collector/{raw,event}\n", rcv.HECAddr())
		}
		fmt.Printf(" [Receiver] Press Ctrl+C to terminate.\n\n")

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		startTime := time.Now()
		for {
			select {
			case <-ctx.Done():
				st := rcv.Stats()
				fmt.Printf("\n\n [Receiver] Stopped. Cumulative Ingest: %d events (%.2f MB) in %v\n",
					st.EventsReceived, float64(st.BytesReceived)/(1024*1024), time.Since(startTime).Round(time.Millisecond))
				return
			case <-ticker.C:
				st := rcv.Stats()
				fmt.Printf("\r [Receiver Live] Elapsed: %-6s | Current Ingest EPS: %-8.0f | Events: %-10d | Inbound: %-6.2f MB",
					time.Since(startTime).Round(time.Second), st.CurrentEPS, st.EventsReceived, float64(st.BytesReceived)/(1024*1024))
			}
		}
	default:
		fmt.Fprintf(os.Stderr, " [Error] Unknown mode %q (expected: run, server, receiver)\n", *mode)
		os.Exit(1)
	}
}

