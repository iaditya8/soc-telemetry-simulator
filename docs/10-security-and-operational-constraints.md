# 10 — Security and Operational Constraints

## 1. Current deployment scope

Do not design Docker or Kubernetes deployment in this version. The user explicitly deferred this decision.

The design should remain deployment-neutral and describe the required runtime components without selecting a container orchestration platform.

## 2. Local resource awareness

The known target development machine is Windows 11, Intel Core i5 (exact model unknown), 16 GB RAM, 512 GB SSD and NVIDIA GPU (exact model/VRAM unknown).

Do not assume the machine can sustain a particular EPS. Propose benchmark stages and safe operating guardrails.

The design should:
- Make generation rate configurable.
- Bound queues and memory.
- Expose CPU, memory, disk and queue metrics.
- Allow graceful stop.
- Avoid unbounded buffering.
- Support a reduced-resource mode.
- Benchmark source generation separately from forwarding and destination ingestion.

## 3. Credentials and secrets

- Store destination credentials securely.
- Redact secrets from logs and reports.
- Never include real passwords or personal data in generated events.
- Use synthetic usernames, domains and IP ranges.
- Avoid collisions with real network addresses where possible; document reserved test ranges.

## 4. Network behavior

- Do not send telemetry to destinations that were not configured by the operator.
- Provide destination connectivity checks.
- Make TLS verification behavior explicit.
- Do not disable certificate verification silently.
- Restrict any generated network traffic to the configured destination and explicitly approved lab ranges.

## 5. Data retention

Define retention for:
- Run metadata.
- Event correlation ledger.
- Final reports.
- Raw sample records.
- Optional local forwarding buffers.

Do not turn the simulator into a permanent SIEM data lake. Avoid retaining full generated payloads indefinitely unless the user explicitly enables it.

## 6. Failure behavior

Document behavior for:
- Destination unavailable.
- Authentication failure.
- Rate limit/rejection.
- Queue full.
- Disk full.
- Process restart.
- User stops a run.
- Partial run/report generation.
- Invalid source template.
