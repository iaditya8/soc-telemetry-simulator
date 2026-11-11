# 06 — Dashboard Requirements

## 1. Dashboard purpose

Provide a simple control center to configure, start, monitor, stop and review telemetry simulation runs.

## 2. Main pages

### Overview
Show:
- Current run state.
- Logical endpoint count.
- Target and actual generated EPS.
- Normal and suspicious generated counts.
- Events submitted/acknowledged/failed.
- Queue depth and destination health.
- Recent run history.

### Endpoint Fleet
Allow the operator to:
- Create/edit logical endpoint profiles.
- Bulk-create endpoints from a count and device distribution.
- Assign hostname/address ranges without collisions.
- Select device/source profile.
- Enable/disable endpoints.
- View per-endpoint event rate and generated count.

### Event Catalog
Allow browsing by:
- Source family.
- Vendor/product profile.
- Event category.
- Event ID/type.
- Normal/suspicious classification.
- ATT&CK tactic/technique where relevant.
- Format fidelity label.

Show sample raw records and field descriptions.

### Run Configuration
Controls:
- Run name.
- Endpoint fleet/profile.
- Selected source families and event types.
- Total EPS and optional source/endpoint rate allocation.
- Normal/suspicious ratio.
- Scenario selection/intensity.
- Duration or continuous run.
- Destination.
- Optional random seed.
- Preflight validation.

### Live Run Monitor
Show:
- Run ID and status.
- Elapsed/remaining time.
- Target vs actual generated EPS.
- Generated events by source and classification.
- Queue depth.
- Submitted, acknowledged, rejected, failed and unknown counts.
- Retry counts and errors.
- Stop control.

### Reports and History
Show completed runs, configuration snapshots, summary statistics, report exports and manual comparison worksheet.

## 3. UX principles

- Keep common setup to a short guided workflow.
- Allow multiple source types and event types in one run.
- Explain invalid rate/percentage configurations.
- Distinguish generated vs sent vs acknowledged counts visually and textually.
- Never show a SIEM detection status unless manually entered or verified from an actual integration.
- Clearly label synthetic/native-format-compatible records.
- Include a preflight summary before run start.
