# 09 — Suspicious Events and Reference Frameworks

## 1. Purpose

Generate suspicious security-relevant telemetry alongside normal enterprise activity. Suspicious activity must be coherent, source-appropriate and grounded in recognized references.

## 2. Framework use

MITRE ATT&CK is a classification and scenario-design reference. It describes adversary tactics and techniques; it does not define the exact raw log format for Windows, Linux or a firewall.

Use:
- MITRE ATT&CK Enterprise for technique/tactic mapping.
- Microsoft event documentation for Windows event semantics and audit prerequisites.
- Linux distribution/service documentation for auth, syslog and audit event semantics.
- RFC 3164/RFC 5424 for applicable syslog formats.
- Vendor documentation for any named firewall, router, VPN, database or identity log profile.
- Other recognized standards/frameworks only where they add concrete value.

Record framework version/retrieval date in the design and keep mappings updateable.

## 3. Suspicious categories for initial catalog

Examples:
- Repeated failed authentication.
- Failed logons followed by successful authentication.
- Unusual account or group changes.
- Suspicious process/PowerShell activity indicators.
- Account and system discovery.
- Unusual network service discovery or scanning patterns.
- Suspicious DNS query bursts or domains.
- Unusual outbound connection patterns.
- Firewall deny/allow sequences that form a coherent story.
- VPN authentication anomalies.
- Privilege-related activity.
- Unusual web or database access patterns.

These are event-generation scenarios. They do not require real exploitation, credential theft or destructive actions.

## 4. Scenario definition

Each suspicious scenario should define:
- Scenario ID/name and version.
- Description and purpose.
- ATT&CK tactic/technique IDs where appropriate.
- Required source profiles.
- Event sequence and timing.
- Logical endpoint/entity relationships.
- Parameter ranges.
- Raw event templates.
- Classification rationale.
- Expected record count/rate behavior.
- Validation rules.
- Safety classification.

## 5. Mix with normal activity

Normal activity is essential. The operator should configure the normal/suspicious mix and choose which scenarios are active.

Normal activity examples:
- Successful logons.
- Routine DNS lookups.
- Web requests.
- Service status messages.
- Network allow events.
- Application/database connections.
- Regular system events.

Do not make every suspicious event a standalone isolated record. Some scenarios should produce linked sequences across multiple sources.

## 6. Safety boundary

This version is focused on generating telemetry, not executing attacks. Use synthetic or harmless scenario records. Do not implement real malware, credential dumping, password theft, destructive payloads, uncontrolled scanning or external-target attacks.
