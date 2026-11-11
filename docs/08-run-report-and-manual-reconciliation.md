# 08 — Final Run Report and Manual Reconciliation

## 1. Mandatory report

Every completed, stopped or failed run must produce a final simulator-side report. Report generation is a core product capability.

The user will manually compare this report with Spectra's own report. Automatic Spectra querying or comparison is out of scope for this version.

## 2. Report identity and configuration

Include:
- Run ID.
- Run name.
- Start/end timestamps and timezone.
- Duration.
- Run status (completed, stopped, failed, partial).
- Simulator version.
- Source profile/template versions.
- Logical endpoint inventory snapshot.
- Target EPS and rate distribution.
- Event type selection.
- Normal/suspicious configuration.
- Destination configuration summary with secrets redacted.
- Random seed, if configured.

## 3. Generation statistics

Include:
- Total unique events generated.
- Normal generated count.
- Suspicious generated count.
- Counts by source family.
- Counts by endpoint.
- Counts by event type/event ID.
- Counts by scenario and ATT&CK technique.
- Generated EPS average, peak, minimum and time-series buckets.
- Generation errors and invalid records.

All category totals should reconcile to the total generated count. If categories overlap, label them as non-additive.

## 4. Forwarding statistics

Include:
- Unique events enqueued.
- Unique events submitted.
- Receiver acknowledgements (if supported).
- Rejected events.
- Failed events.
- Retried transmission attempts.
- Remaining queued/unconfirmed events.
- Unknown outcomes.
- Delivery latency and retry/error breakdown.
- Counts by destination and source family.

Clearly state that acknowledgement is not necessarily proof of SIEM indexing or search visibility.

## 5. Suspicious activity breakdown

For each suspicious scenario/type, include:
- Scenario ID/name.
- ATT&CK mapping, if applicable.
- Source profile.
- Logical endpoint(s).
- Generated event count.
- Start/end time.
- Event sequence summary.
- Raw event sample or reference to an export.
- Classification rationale.

The simulator's suspicious classification is ground truth about how the simulator labeled generated events; it is not a SIEM detection result.

## 6. Manual Spectra comparison worksheet

Include a separate blank section/table for the operator to fill in after checking Spectra.

Suggested columns:
- Metric.
- Simulator report value.
- Spectra report value (manual entry).
- Difference.
- Notes.

Suggested rows:
- Total events generated/submitted.
- Total events visible in Spectra.
- Windows event count.
- Linux event count.
- Firewall event count.
- DNS event count.
- Normal/suspicious counts where the SIEM exposes comparable classifications.
- Specific event IDs/types.
- Time range and timezone.
- Any known parsing or filtering differences.

Do not pre-fill Spectra values or calculate a detection rate without user-entered/verified SIEM data.

## 7. Exports

Provide:
- Human-readable HTML report.
- PDF report if practical.
- Machine-readable JSON summary.
- CSV breakdowns for event/source/endpoint/delivery statistics.
- Optional raw sample export, subject to size limits.

## 8. Report integrity

Persist the final report and run ledger. Report should identify incomplete metrics when a process crashes or delivery cannot be fully reconciled. Never silently turn unknown outcomes into success or failure.
