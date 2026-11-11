# 05 — Log Generation Engine

## 1. Responsibility

The generation engine creates source-faithful records at the requested rate and distribution. It is separate from the dashboard and separate from destination forwarding.

## 2. Logical endpoint model

A logical endpoint is a virtual device identity, not necessarily a running OS.

Each endpoint has:
- Unique endpoint ID.
- Hostname.
- Simulated IP/address identity.
- Device family.
- OS/platform profile.
- Vendor/product profile, if applicable.
- Enabled source profiles.
- Event distribution.
- Rate allocation.
- Normal/suspicious activity settings.
- Optional business context (department, site, environment).

The engine must support hundreds or more logical identities without requiring one full OS instance per identity.

## 3. Generation scheduling

Design a scheduler that can support:
- Total target EPS.
- Optional per-source EPS.
- Optional per-endpoint EPS.
- Weighted event distribution.
- Multiple event categories concurrently.
- Duration-based and continuous runs.
- Burst profiles and steady-state profiles.
- Backpressure when forwarding is slower than generation.

The design must explain whether the EPS target means generated events, submitted events or receiver-acknowledged events. Dashboard labels must distinguish them.

## 4. Event distribution

The operator may configure:
- Normal/suspicious percentage.
- Per-source distribution.
- Per-event-type distribution.
- Per-endpoint distribution.
- Scenario intensity.
- Optional time-of-day or workload patterns.

The engine must validate configuration totals and show how percentages are applied. Avoid silently normalizing invalid input without telling the user.

## 5. Coherent sequences

Some suspicious activity should be generated as sequences rather than unrelated records. Examples:
- Failed logons from one source against one account over a time window.
- A successful logon following repeated failures.
- Account discovery followed by privilege-related activity.
- DNS query burst followed by an outbound connection.
- Firewall deny events associated with a scanning pattern.

Sequence generation should use scenario templates and shared entities so the records are internally consistent.

## 6. Throughput and resource control

The design must include:
- Bounded queues.
- Configurable queue limits.
- Backpressure policy.
- Drop/reject accounting.
- CPU and memory limits/guardrails.
- Graceful stop and flush timeout.
- Metrics for generator lag and forwarding lag.

Do not promise a fixed maximum EPS before benchmarking on the target machine and destination.

## 7. Repeatability

Support saving a run configuration and optional deterministic random seed. A repeated run should produce comparable distributions and, where intended, reproducible event sequences. Store generator version and profile versions in the report.
