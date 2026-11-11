# 03 — Log Source Catalog and Format Requirements

## 1. General rule

Each source profile must define the actual format, schema, required fields, timestamp semantics, severity conventions, event identifiers and supported transport. Do not use one generic JSON schema for all sources.

The agent must create a source catalog with explicit format fidelity labels:
- **Native record:** produced by the real source or its official logging subsystem.
- **Native-format compatible:** generated record conforms to the documented source format/schema but is not emitted by the real operating system/device.
- **Vendor-style profile:** intentionally models a named vendor's documented log format.
- **Generic standard:** uses a standard such as RFC 3164/RFC 5424 syslog or a documented JSON schema.

The UI/report must not mislabel compatible synthetic records as genuine OS-generated logs.

## 2. Initial source families

### Windows
Candidate event families:
- Security auditing events (e.g. successful/failed logon, account/group changes, process creation when audit policy supports it).
- System events.
- Application events.
- PowerShell operational events.
- Sysmon events when the profile is explicitly configured for Sysmon schema.

Design considerations:
- Windows Event Log records have provider, channel, event ID, version, level, task, opcode, keywords, timestamp, computer and event data.
- XML representation is not the same thing as a genuine EVTX record or a live Windows Event Log entry.
- If Winlogbeat is used, it normally reads actual Windows Event Log channels. It cannot be assumed to ingest arbitrary generated XML as if it were a native channel.
- Design a suitable direct output/adapter for generated Windows-format events, or clearly document an actual Windows event injection/source mechanism if one is later chosen.

### Linux
Candidate formats:
- RFC 3164/RFC 5424 syslog.
- Common auth log formats (distribution and daemon profile-specific).
- auditd-style records.
- systemd journal export format, if explicitly supported.
- Application/service logs.

Do not imply a container or logical endpoint has a real PAM/sshd/audit subsystem unless it actually does.

### Firewall and network devices
Candidate formats:
- RFC 5424 or RFC 3164 syslog.
- Vendor-specific firewall allow/deny and threat event formats.
- Router interface, routing, configuration and system messages.
- Network flow records, if a format and schema are selected.

The first release should choose a small, documented set of vendor-neutral and/or vendor-specific profiles. Avoid claiming universal firewall compatibility.

### DNS
Candidate formats:
- DNS server query/response logs.
- Resolver logs.
- Security analytics records for NXDOMAIN spikes, unusual query volume and suspicious domains.
- If generating DNS protocol events, distinguish actual DNS protocol traffic from DNS server log records.

### Web and reverse proxy
Candidate formats:
- Common/Combined Log Format where applicable.
- JSON access logs with a documented field map.
- Error logs and authentication/application audit logs.

### Database
Choose named database profiles and documented audit formats. Examples may include connection, authentication, query audit and privilege-change events. Do not invent a vendor schema.

### VPN and identity
Choose explicit profiles for authentication, session start/end, MFA outcomes, device posture and directory audit events. Use documented event fields for the chosen identity/VPN product profile.

## 3. Source profile definition

Every source profile should specify:
- Profile ID and version.
- Device family and vendor/product (if any).
- Raw format name and version.
- Encoding and line framing.
- Timestamp format and timezone.
- Required and optional fields.
- Event ID/name conventions.
- Severity/facility conventions where relevant.
- Example valid records.
- Validation method and reference documentation.
- Supported destinations/transports.
- Fidelity label.

## 4. Initial source prioritization proposal

The agent should propose and justify an MVP order. A sensible starting proposal is:
1. RFC 5424/RFC 3164 syslog profile for generic infrastructure.
2. Linux auth/syslog profile.
3. Windows Security Event XML-compatible profile plus a clearly defined delivery path.
4. Firewall allow/deny profile.
5. DNS query profile.
6. Web access profile.
7. Database and VPN/identity profiles.

This is a proposal for design review, not an already-approved implementation sequence.
