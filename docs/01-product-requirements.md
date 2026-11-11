# 01 — Product Requirements

## 1. Product definition

A configurable, multi-source, multi-endpoint enterprise telemetry simulator that generates realistic normal and suspicious raw security logs at configurable rates and forwards them to Spectra for SIEM ingestion testing.

The simulator should create the experience of an enterprise environment containing many different systems, even when those systems are represented by logical endpoint identities rather than full operating systems.

## 2. Primary goals

- Generate large volumes of source-specific logs at predictable and configurable rates.
- Represent many logical devices with distinct identities.
- Generate a realistic mix of routine enterprise activity and security-relevant activity.
- Preserve the native/source-specific structure and meaning of each event type.
- Forward records reliably to the configured SIEM destination.
- Show generation and forwarding metrics while a run is active.
- Produce a detailed final report for every run so the operator can manually compare it with Spectra's report.

## 3. Initial source families

The design must cover at least:

1. Windows endpoints and servers.
2. Linux servers.
3. Firewalls.
4. Routers and network devices.
5. DNS servers.
6. Web servers and reverse proxies.
7. Database systems.
8. VPN gateways.
9. Identity and directory services.
10. An extensible custom source family.

The agent must propose a prioritized first release source catalog. It must not claim every vendor/device format is supported unless the format is explicitly implemented and tested.

## 4. Main operator controls

The operator must be able to configure:

- Number of logical endpoints.
- Endpoint inventory and device-type distribution.
- Source family and source/vendor profile.
- Event categories and individual event types.
- Target total EPS and, where useful, per-source/per-endpoint rates.
- Normal/suspicious event proportions.
- Suspicious scenario selection and intensity.
- Run duration or continuous mode with manual stop.
- Destination and forwarding settings.
- Optional deterministic seed/configuration for repeatable runs.

The dashboard should make it easy to select multiple event categories in one run.

## 5. Reporting goals

At the end of each run, provide:

- Total events generated.
- Normal and suspicious generated counts.
- Counts by source family, device, event type and scenario.
- Target and observed EPS over time.
- Events queued/submitted/acknowledged/rejected/failed/unknown.
- Retry and backpressure statistics.
- Run duration and endpoint counts.
- Configuration snapshot and run identifier.
- Exportable report and raw statistics.

## 6. Non-goals for this version

- Building or modifying Spectra.
- Replacing a SIEM or storing all telemetry as a second SIEM.
- Automatically querying Spectra or comparing against Spectra's internal report.
- Kubernetes or Docker deployment design.
- Running 100 full operating systems.
- Full red-team infrastructure or unrestricted attack execution.
- Real malware, credential theft, destructive activity or attacks against external systems.
- Claiming generated Windows XML is equivalent to a genuine Windows Event Log/EVTX record without a compatible ingestion path.

## 7. Product principles

- **Source fidelity over generic JSON:** preserve each source's native structure and semantics.
- **Scale without full machines:** logical endpoints are the main scale mechanism.
- **Honest delivery accounting:** sending is not the same as receiver acknowledgement, indexing or detection.
- **Repeatability:** same configuration and seed should reproduce comparable event distributions and sequences.
- **Extensibility:** new source profiles and event families should be added without redesigning the core.
- **Simple operation:** a user should be able to configure and run a test from the dashboard without editing code.
