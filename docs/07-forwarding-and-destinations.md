# 07 — Forwarding and Destination Requirements

## 1. Goal

Forward generated raw records to Spectra using a configurable, testable delivery path. The generator must not be tightly coupled to Spectra's internal ingestion implementation.

## 2. Candidate forwarding paths

The design should evaluate and document the right path for each source/destination combination:
- Syslog over UDP/TCP/TLS where supported.
- Splunk HTTP Event Collector (HEC), default port 8088, as a configurable HTTP destination.
- File output for source-compatible records where a supported shipper can read them.
- Fluent Bit, Filebeat and Winlogbeat only where their actual input/output capabilities match the record type.

Important distinctions:
- Winlogbeat normally reads actual Windows Event Log channels; arbitrary XML text is not automatically a Windows Event Log channel.
- Filebeat and Fluent Bit can tail/collect files or receive supported inputs, but the selected input/output plugins must be verified.
- Syslog is a protocol/message format family, not a universal guarantee of SIEM acceptance.
- HEC is an HTTP ingestion endpoint; an acknowledgement confirms the receiver's response, not necessarily indexing/searchability.

## 3. Initial destination

Spectra is the initial target SIEM. The agent must not invent Spectra ports, endpoint paths, payload schema, authentication method or acknowledgements.

Design the destination configuration as explicit fields:
- Destination name/type.
- Host and port.
- Protocol.
- TLS enabled/verification.
- Authentication/secret reference.
- Format/codec.
- Batching and flush settings.
- Timeout and retry policy.
- Optional source/index/sourcetype fields only where supported by the chosen receiver.
- Connectivity/preflight test.
- Health/error status.

Use secure secret handling. Do not store tokens in plaintext configuration exports or reports.

## 4. Delivery accounting

Track separately:
- Generated.
- Enqueued.
- Submitted.
- Acknowledged by receiver (if protocol supports a reliable acknowledgement).
- Rejected.
- Failed.
- Retried.
- Still queued/unconfirmed at stop.
- Unknown outcome.

Avoid double counting retries as new generated events. Define whether metrics count unique events or transmission attempts.

## 5. Reliability behavior

Design:
- Bounded queues.
- Retry with backoff.
- Duplicate/idempotency considerations.
- Clear handling for permanent vs transient errors.
- Flush timeout on stop.
- Explicit overflow policy.
- Per-destination metrics.
- Failure logs and operator visibility.

Do not claim end-to-end delivery or indexing unless the destination explicitly provides and the simulator verifies that evidence.
