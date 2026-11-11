# 02 — Operator Workflow

## 1. Configure an environment

The operator opens the dashboard and creates an environment profile.

They define a virtual fleet, for example:
- 30 Windows workstations
- 15 Windows servers
- 15 Linux servers
- 10 firewalls
- 5 routers
- 5 DNS servers
- 5 web servers
- 5 database servers
- 5 VPN/identity devices
- 5 other network devices

These are logical endpoint identities. They do not imply 100 running operating systems.

Each logical endpoint has:
- Stable endpoint ID
- Hostname
- Simulated IP/address identity (with collision validation)
- Device family and OS/platform profile
- Vendor/product profile, if applicable
- Enabled log sources
- Configured event mix and rate allocation

## 2. Select telemetry

The operator chooses one or more source families, event categories and event types.

Examples:
- Windows Security: successful and failed logons, account changes, process-related audit events.
- Linux authentication: successful/failed SSH authentication, sudo activity, user/session events.
- Firewall: allow/deny, connection lifecycle, rule match, threat/security events.
- DNS: query/response, NXDOMAIN, unusual query patterns.
- Web: access, error, authentication and application audit records.

The selected events must be valid for the selected source profile.

## 3. Set generation parameters

The operator sets:
- Total target EPS.
- Optional per-source/per-endpoint EPS distribution.
- Normal/suspicious mix.
- Run duration.
- Event type distribution.
- Optional scenario intensity and randomization seed.

The system validates that allocations are consistent. If the selected percentages or rates do not add up, the UI should explain and resolve the configuration before start.

## 4. Validate and start

Before starting, the simulator validates:
- Endpoint inventory and unique identities.
- Event/source compatibility.
- EPS and duration limits.
- Destination configuration and connectivity test.
- Available local resource budget.
- Required event profiles and templates.
- Any safety constraints.

The operator sees a run summary and confirms.

## 5. Monitor live run

The dashboard shows:
- Run ID and status.
- Elapsed and remaining time.
- Configured endpoint count and active logical endpoints.
- Target EPS and actual generated EPS.
- Generated normal/suspicious counts.
- Generated counts by source family.
- Forwarding queue depth.
- Submitted/acknowledged/rejected/failed counts.
- Error and retry rates.
- Destination health.

The operator can stop a run. Stop should halt new generation, drain or explicitly abandon queued events according to the selected stop policy, then finalize the report.

## 6. Complete and report

At completion:
1. Stop generation.
2. Flush pending buffers within a configured timeout.
3. Record any remaining queued/unconfirmed events.
4. Finalize the simulator-side run ledger.
5. Generate the final report and export files.
6. Present a clear manual comparison checklist for the user to compare against Spectra.

No Spectra API query is required in this version.

## 7. Repeat a run

The operator can save a run configuration and repeat it. The report must retain the configuration snapshot, software version and random seed (if used) so comparisons are meaningful.
