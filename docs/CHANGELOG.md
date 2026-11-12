# Release Notes & Project Changelog

## [1.0.0] - 2026-11-12 — Feature-Complete General Availability (GA)

### Summary of Release
The **SOC Telemetry Simulator v1.0.0** is the initial feature-complete production release. Designed as a high-throughput, standalone security telemetry generator and SIEM ingestion benchmark, it delivers bare-metal multi-source log generation, deterministic logical endpoint synthesis, stateful MITRE ATT&CK adversary emulation, atomic 7-state delivery accounting, and an embedded management dashboard.

---

### Milestone Epics & Issue Traceability

#### Epic #1: Core Generation Pipeline & Logical Fleet Synthesis (Closed via PR #26, #27, #28)
- **#7 (Task 1): Zero-Allocation Byte Buffer Pool:** Implemented `pkg/buffer/buffer.go` using `sync.Pool`, providing fast decimal/hex formatting and zero-allocation timestamp serialization.
- **#8 (Task 2): Deterministic Fleet Inventory Manager:** Implemented `pkg/fleet/fleet.go` with deterministic PRNG seeding, dynamic MAC/IP generation across 5 enterprise subnets, and subnet gateway reservation.
- **#9 (Task 3): Bresenham High-Precision Rate Scheduler:** Implemented `pkg/generator/scheduler.go` providing jitter-free sub-millisecond pacing and multi-worker output aggregation.

#### Epic #2: Enterprise Native Formatters & MITRE ATT&CK Engine (Closed via PR #29, #30, #31, #32)
- **#10 (Task 4): Windows Event Log XML Formatter:** Implemented `pkg/formatter/windows_xml.go` producing Microsoft Event Schema 2.0 XML for Events 4624, 4625, 4688, and 4720 with XML entity escaping.
- **#11 (Task 5): Linux Syslog RFC 3164/5424 Formatter:** Implemented `pkg/formatter/linux_syslog.go` generating BSD and structured syslog messages for `sshd`, `sudo`, and `systemd`.
- **#12 (Task 6): Network Firewall (PAN-OS CSV) & DNS (BIND9) Formatters:** Implemented `pkg/formatter/paloalto.go` (54-column CSV for TRAFFIC and THREAT) and `pkg/formatter/bind9.go` (ISC BIND 9 query logs).
- **#13 (Task 7): MITRE ATT&CK Adversary Scenarios:** Implemented `pkg/scenario/scenario.go` and `orchestrator.go` modeling T1110.001 (Brute Force), T1046 (Port Scan), T1071.004 (DNS C2), and T1059.001 (Obfuscated PowerShell).

#### Epic #3: Universal Forwarding Engine & Standalone Mock SIEM Receiver (Closed via PR #33, #34, #35, #36)
- **#14 (Task 8): Ring Buffer FIFO Queue with Backpressure:** Implemented `pkg/queue/ring.go` with atomic queue depth tracking and selectable drop policies (`drop_oldest`, `drop_newest`, `block`).
- **#15 (Task 9): Streaming TCP / TLS Network Forwarder:** Implemented `pkg/forwarder/tcp.go` with connection pooling, newline framing, RFC 5424 / RFC 6587 octet counting, and embedded newline rejection.
- **#16 (Task 10): Splunk HTTP Event Collector (HEC) Forwarder:** Implemented `pkg/forwarder/hec.go` supporting batched aggregation, gzip compression, and HTTP status code mapping.
- **#17 (Task 11): Standalone Mock Spectra SIEM Receiver:** Implemented `pkg/mockserver/receiver.go` listening on TCP 5140 and HEC 8088 to validate end-to-end forwarder throughput without external infrastructure.

#### Epic #4: Delivery Accounting & Post-Run Reconciliation (Closed via PR #37, #38, #39)
- **#18 (Task 12): Pure Go xxHash64 & 32-Byte Ring Ledger:** Implemented `pkg/ledger/xxhash.go` and `ledger.go` for zero-allocation payload fingerprinting and compact audit memory.
- **#19 (Task 13): Atomic 7-State Delivery Accounting Engine:** Implemented `pkg/ledger/accounting.go` tracking Generated, Enqueued, Submitted, Acknowledged, Rejected, Failed, Dropped, Retries, and Unknown states with mathematical conservation checks (`ValidateInvariants()`).
- **#20 (Task 14): Post-Run Multi-Format Report Generator:** Implemented `pkg/report/report.go` generating standalone HTML reports with CSS styling, JSON metrics, and the standardized Spectra Manual Reconciliation CSV worksheet.

#### Epic #5: Embedded Management Web Dashboard & Live Monitor (Closed via PR #40, #41, #42)
- **#21 (Task 15): Embedded Management HTTP Server & REST API:** Implemented `pkg/web/server.go` strictly bound to `127.0.0.1:8080`, exposing `/api/health`, `/api/fleet`, `/api/catalog`, `/api/run/start`, `/api/run/stop`, and `/api/reports`.
- **#22 (Task 16): Real-Time WebSocket & SSE Telemetry Hub:** Implemented `pkg/web/hub.go` broadcasting live generator throughput, accounting states, and invariants at 10 Hz.
- **#23 (Task 17): Interactive Single-Page Web Dashboard:** Implemented `pkg/web/ui/index.html`, `app.js`, and `style.css` embedded directly into the Go binary (`//go:embed ui/*`), providing complete offline fleet management, preflight log previews, live gauges, and report downloads.

#### Epic #6: Hardware Benchmarking & 100k+ EPS Validation (Closed via PR #43)
- **#24 (Task 18): High-Performance Benchmark Test Suites:** Implemented `pkg/generator/generator_bench_test.go` (1.84M EPS generator) and `pkg/forwarder/forwarder_bench_test.go` (8.46M EPS TCP forwarder).
- **#25 (Task 19): 100,000 EPS Hardware Validation Report:** Implemented `-mode benchmark` in `cmd/soc-sim/main.go`, achieving **99,944.8 EPS** on Intel Core i5-12500H, **4.12 MB peak heap memory**, and **0 GC pause spikes**, published in `BENCHMARK_RESULTS.md`.

---

### Code Quality & Standards Compliance
- **Go 1.24 Compatibility:** Modernized all 18 benchmark loops across the codebase to `for b.Loop()`.
- **Zero Diagnostics:** 0 errors, 0 warnings across `go vet` and IDE static analysis.
- **Strict Security:** Loopback-only binding enforcement (`127.0.0.1`), automatic secret redaction, and strict log injection sanitization.
