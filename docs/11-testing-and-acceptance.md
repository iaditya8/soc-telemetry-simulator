# 11 — Testing Strategy and Acceptance Criteria

## 1. Design acceptance

Before coding, the agent must provide:
- Component architecture and data flow.
- Source profile catalog and fidelity labels.
- Event generation model and rate allocation rules.
- Logical endpoint model.
- Dashboard wireframe/page map.
- Destination/forwarding design.
- Run ledger and report schema.
- Manual Spectra comparison worksheet.
- Resource and performance plan.
- Risk/unknowns register.
- Phased implementation plan.

## 2. Functional acceptance

The eventual implementation must demonstrate:
- Create a fleet of logical endpoints with unique identities.
- Select multiple source families and event types.
- Generate normal and suspicious event mixes.
- Generate source-valid raw records.
- Configure target EPS and duration.
- Start, monitor and stop runs.
- Forward to a real configured receiver.
- Produce a final report for successful, stopped and failed runs.
- Export report data in documented formats.
- Repeat a saved configuration.

## 3. Format acceptance

For every supported source profile:
- Golden sample records.
- Schema/format validation.
- Required-field tests.
- Timestamp and timezone tests.
- Encoding/framing tests.
- Semantic consistency tests.
- Forwarding compatibility test for claimed output paths.

## 4. Throughput acceptance

Do not hardcode a performance promise. Define benchmark stages such as:
- Low-rate functional run.
- Sustained moderate-rate run.
- Higher-rate stress run.
- Long-duration stability run.

Measure separately:
- Generated EPS.
- Submitted EPS.
- Acknowledged EPS where available.
- CPU/memory.
- Queue depth and lag.
- Invalid/dropped records.
- Delivery latency and retries.

## 5. Reporting acceptance

For every run:
- Generated count reconciles with event ledger.
- Normal plus suspicious counts reconcile to total if classifications are mutually exclusive.
- Source/event breakdowns reconcile or clearly state overlap.
- Forwarding states do not double count retries as new events.
- Unknown delivery states remain unknown.
- Final report contains configuration snapshot and timestamps.
- Manual comparison section is present and blank until user fills Spectra values.

## 6. No mock-only claims

A mocked receiver test does not prove real forwarding. A successful HTTP request does not prove indexing. A schema test does not prove the SIEM parses the record. Reports must state exactly what was verified.
