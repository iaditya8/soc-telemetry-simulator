# 04 — Log Realism and Event Model

## 1. Preserve raw records

The simulator's primary output is a source-specific raw record. It must not flatten every source into a generic message object.

For each event, the system may maintain an internal metadata envelope/ledger containing:
- Run ID
- Event correlation ID
- Logical endpoint ID
- Source profile ID/version
- Simulator generation timestamp
- Source event timestamp
- Normal/suspicious classification
- Scenario ID and ATT&CK mapping, if applicable
- Sequence number (where used)
- Raw payload hash/fingerprint
- Delivery state and attempt history

The raw payload should remain unchanged unless a source profile explicitly defines a valid field for correlation metadata.

## 2. Event semantics

A realistic event needs more than a plausible-looking message. The generator should maintain:
- Valid event identifiers and field relationships.
- Coherent source and destination addresses.
- Consistent endpoint hostname and source identity.
- Plausible user/account/process/service values.
- Correct timestamp ordering and timezone handling.
- Valid severity/facility values for the format.
- Correct escaping, encoding and framing.
- Correlated records that tell a coherent story.
- Source-specific field naming and value conventions.

## 3. Event templates and parameterization

Each event template should define:
- Source profile.
- Event type and event identifier.
- Required fields and constraints.
- Optional fields and distributions.
- Parameter generation rules.
- Normal/suspicious classification.
- Scenario relationships.
- Example raw output.
- Schema/format validation rules.

Use bounded, deterministic parameter generation where possible. Randomness should not create invalid records.

## 4. Correlation and provenance

For manual reporting and troubleshooting, the simulator needs to know which events it generated. Use an internal ledger keyed by an event correlation ID.

Do not force an arbitrary field into native event formats. Where the source format supports a safe custom field, it may be used only if the selected profile permits it. Otherwise correlate using the ledger and a documented combination of endpoint identity, timestamps, event identifiers and payload fingerprints.

## 5. Realism labels

Every event profile must clearly identify whether it is:
- Generated from an actual operating-system/device logging subsystem.
- Synthetic but conformant to a documented source format.
- Vendor-style synthetic.
- Generic standard-format synthetic.

Reports and UI must expose this distinction so a user knows what kind of telemetry they are testing.

## 6. Validation

Before a profile is marked supported:
- Validate output against its schema/specification where one exists.
- Check required fields and value constraints.
- Test encoding and framing.
- Test timestamps and timezone handling.
- Verify forwarding compatibility for each claimed transport.
- Include golden sample records and regression tests.
