# 12 — Instructions for the Coding/Design Agent

## Task: Design the SOC Telemetry Simulator. Do not code.

You are being asked to design a standalone high-volume enterprise raw-log generation and SIEM ingestion testing tool.

### Understand the product correctly

The central product is a **realistic raw telemetry generator at scale**.

It represents an enterprise with many logical endpoints and device types. It generates source-specific normal and suspicious logs at configurable rates and forwards them to Spectra. At the end of every run, it produces a detailed simulator-side report. The user manually compares that report with Spectra's report.

This is not primarily a red-team platform, not another SIEM and not a Spectra feature.

### Frozen decisions

- Multi-source and multi-log-family generation.
- Logical endpoint identities; do not require one full OS per endpoint.
- Windows, Linux, firewall, router, DNS, web, database, VPN/identity and extensible source profiles.
- Realistic source-specific raw formats and schemas.
- Normal and suspicious event generation.
- MITRE ATT&CK and source/vendor standards used as references.
- Configurable endpoint count, event mix, event types, EPS, suspicious ratio and duration.
- Forward to Spectra as the initial SIEM destination.
- Manual SIEM report comparison only.
- End-of-run simulator report is mandatory.
- Docker and Kubernetes are out of scope for now.
- No application code or infrastructure changes during this task.

### Required work

1. Read every document in this package.
2. If a repository is provided, inspect it read-only and report its current structure and constraints.
3. Identify ambiguous or technically incompatible requirements, especially around Windows Event Log generation and forwarder compatibility.
4. Propose a simple architecture with clear component responsibilities.
5. Define the logical endpoint and source profile models.
6. Define the raw event/template model and fidelity labels.
7. Define the event generation and EPS scheduling model.
8. Define the normal/suspicious event catalog and ATT&CK mapping strategy.
9. Define destination/forwarding adapters without inventing Spectra endpoints or schemas.
10. Define run ledger, delivery accounting and final report schema.
11. Provide simple dashboard wireframes or page/component outlines.
12. Provide a phased implementation plan with acceptance gates.
13. Identify resource constraints and a benchmark plan for the target Windows 11 / 16 GB RAM PC.
14. Provide a list of unresolved decisions requiring user approval.

### Important technical questions to resolve

- What is the first Windows record format and how will it reach Spectra? Windows Event XML, EVTX/native channel records and generic JSON are not interchangeable.
- Which Linux syslog/auth formats are in the first release?
- Which firewall/DNS/vendor profiles are in the first release?
- Which forwarding paths are actually compatible with each raw format?
- How will unique event IDs be tracked without corrupting native raw records?
- How are generated, submitted, acknowledged, rejected, failed and unknown events counted?
- How will EPS be distributed across logical endpoints and source types?
- How will the report distinguish synthetic source-faithful records from records produced by actual operating-system logging subsystems?

### Deliverables

Return a design package containing:
- Executive architecture summary.
- Architecture diagram.
- Component responsibilities.
- Source/profile catalog.
- Logical endpoint model.
- Event and scenario model.
- Dashboard design.
- Forwarding/destination design.
- Run report example and schema.
- Security/resource design.
- Testing/acceptance plan.
- Phased implementation roadmap.
- Risks, assumptions and open decisions.

### Strict restrictions

- Do not code.
- Do not create or modify files in the target repository.
- Do not install packages or services.
- Do not create Docker/Kubernetes files.
- Do not invent Spectra ingestion API paths, ports, schemas or authentication.
- Do not claim a source format is native/genuine unless the implementation method proves it.
- Do not promise EPS capacity without benchmark evidence.
- Do not proceed to implementation until the user approves the design.

### Expected final response

Summarize what you inspected, the proposed design, major technical decisions, unresolved questions, risks and the implementation plan. Clearly state that no code was changed.
