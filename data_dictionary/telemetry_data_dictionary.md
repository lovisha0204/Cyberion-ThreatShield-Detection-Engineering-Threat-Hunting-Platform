# Cyberion Defense Labs — Telemetry Data Dictionary
**Document ID:** CDL-TEL-DICT-01  
**Classification:** Internal Use — Engineering Program  
**Author:** Detection Engineering & Threat Intelligence Practice  
**Date:** 2026-10-08  
**Applicable Environments:** Simulated Client Enterprise (Windows Domain, Mixed Workstations, Perimeter Zeek Sensors)

---

## 1. Overview & Objective
This data dictionary defines the structure, syntax, and detection relevance of three primary telemetry sources utilized in the **Cyberion Defense Labs (CDL)** detection engineering and threat hunting program:
1. **Windows Security Event Telemetry** (Native Windows Event Log via Event Viewer / Security Channel)
2. **Microsoft Sysmon (System Monitor) Telemetry** (Deep Endpoint Instrumentation via Sysmon Channel)
3. **Zeek Network Security Monitor Telemetry** (Protocol Analysis & Wire Telemetry)

Each section documents the specific fields provided by the log sources, standard data types, field definitions, detection use cases, and noise-filtering / baseline considerations.

---

## 2. Windows Security Event Log Telemetry

The Windows Security Log provides authoritative visibility into authentication, privilege assignment, security group modifications, and account management across workstations, member servers, and Active Directory Domain Controllers.

### 2.1 Core Event IDs in Scope

| Event ID | Event Description | Telemetry Category | High-Value Attacker Techniques |
|:---|:---|:---|:---|
| **4624** | An account was successfully logged on | Authentication | T1078 (Valid Accounts), T1021 (Remote Services) |
| **4625** | An account failed to log on | Authentication | T1110 (Brute Force / Password Spraying) |
| **4672** | Special privileges assigned to new logon | Privilege Escalation | T1078.002 (Domain Admin Logon), T1068 |
| **4688** | A new process has been created | Process Execution | T1059 (Command & Scripting Interpreter), T1218 |
| **4720** | A user account was created | Account Manipulation | T1136 (Create Account) |
| **4728** | A member was added to a security group | Persistence / PrivEsc | T1098 (Account Manipulation: Domain Admins) |
| **4738** | A user account was modified | Persistence | T1098 (Account Manipulation, SPN addition) |
| **4769** | Kerberos Service Ticket (TGS) was requested | Credential Access | T1558.003 (Kerberoasting) |

### 2.2 Field Definitions & Detection Significance

| Field Name | Data Type | Example Value | Description | Detection Relevance |
|:---|:---|:---|:---|:---|
| `EventID` | Integer | `4624` | Windows Event Identifier | Primary filter for categorizing telemetry events. |
| `TargetUserName` | String | `Administrator` | The username associated with the targeted action | Scrutinized for administrative accounts, service accounts (`svc_*`), or honey-tokens. |
| `TargetDomainName` | String | `CYBERION.LOCAL` | Domain of the targeted principal | Distinguishes local machine logons from domain-wide logons. |
| `LogonType` | Integer | `3` (Network), `10` (RDP) | Numeric representation of the logon mechanism | `Type 2` (Interactive/Console), `Type 3` (Network/SMB/WMI), `Type 10` (RemoteInteractive/RDP). Critical for lateral movement detection. |
| `LogonProcessName` | String | `Kerberos`, `NtLmSsp` | Name of the trusted logon process | Pinpoints NTLM downgrade attacks or unusual auth providers. |
| `WorkstationName` | String | `WKSTN-FIN-01` | Originating machine hostname | Tracks lateral movement origin vs. destination. |
| `IpAddress` | String | `192.168.10.45` | Originating IPv4 or IPv6 address | Correlates internal network hops or external ingress IP addresses. |
| `IpPort` | Integer | `49201` | Source ephemeral port | Identifies reverse proxy listeners or outbound tunneling sessions. |
| `ProcessName` / `NewProcessName` | String | `C:\Windows\System32\cmd.exe` | Full path of the created executable | Primary target for Living-Off-The-Land Binaries (LOLBAS). |
| `CommandLine` | String | `cmd.exe /c whoami /priv` | Full command line with arguments (requires audit policy enabled) | Extracts attacker syntax, download cradles, and obfuscation. |
| `ParentProcessName` | String | `C:\Windows\explorer.exe` | Parent executable path | Detects anomalous parent-child execution lineages (e.g., `winword.exe` spawning `powershell.exe`). |
| `TicketOptions` | Hex / String | `0x40810000` | Flags requested during Kerberos ticket issuance | Key in Kerberoasting heuristics (identifies requests without pre-auth or renewal flags). |
| `TicketEncryptionType` | Hex / String | `0x17` (RC4-HMAC) | Cipher used for the requested Kerberos ticket | Detects downgrade to RC4 (`0x17`) susceptible to offline cracking, as opposed to AES256 (`0x12`). |
| `ServiceName` | String | `krbtgt`, `MSSQLSvc/db01.cyberion.local` | SPN associated with the service request | Isolates high-value database, backup, or domain controller SPNs. |
| `Status` / `SubStatus` | Hex / String | `0xC000006A` (Bad Password), `0xC0000234` (Locked) | NTSTATUS failure codes | Differentiates password spray (one bad password across many users) from brute force (many bad passwords on one user). |

---

## 3. Microsoft Sysmon Telemetry

Sysmon provides low-level host instrumentation via a kernel mini-filter driver, recording process lineages, raw memory operations, driver loads, and host-level network connections directly into the Windows Event Log channel `Microsoft-Windows-Sysmon/Operational`.

### 3.1 Sysmon Event Schema in Scope

| Event ID | Event Type | Forensic Purpose | MITRE ATT&CK Mapping |
|:---|:---|:---|:---|
| **1** | Process Creation | Full process execution with hashes, command lines, and parent details | T1059, T1204, T1053, T1218 |
| **3** | Network Connection | Endpoint-level socket creation correlated to image path and PID | T1071 (Application Layer C2), T1021 |
| **7** | Image Loaded | DLL loads into memory space | T1574 (Hijack Execution Flow / DLL Side-Loading) |
| **8** | CreateRemoteThread | Cross-process thread injection | T1055 (Process Injection) |
| **10** | ProcessAccess | Direct access handle acquisition (OpenProcess) | T1003.001 (LSASS Memory Credential Dumping) |
| **11** | FileCreate | New file creation events | T1105 (Ingress Tool Transfer), T1036 (Masquerading) |
| **13** | RegistryEvent (Value Set) | Registry key or value creation/modification | T1547.001 (Registry Run Keys / Persistence) |
| **22** | DNSEvent | DNS queries originated by specific binaries | T1071.004 (DNS C2 / Exfiltration) |

### 3.2 Sysmon Field Details & Detection Meaning

| Field Name | Data Type | Example Value | Description | Detection Relevance |
|:---|:---|:---|:---|:---|
| `RuleName` | String | `technique_id=T1003.001` | Sysmon configuration tag | Provides inline mapping to ATT&CK from endpoint configs. |
| `UtcTime` | Timestamp | `2026-10-08 14:22:01.402` | High-precision UTC timestamp | Enables millisecond-level correlation across attack stages. |
| `ProcessId` | Integer | `4128` | Operating system process ID | Correlates contemporaneous activity on the host. |
| `Image` | String | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | Target executable being executed or inspected | Primary artifact for identifying execution of malicious or dual-use binaries. |
| `CommandLine` | String | `powershell.exe -nop -w hidden -enc JABzAD0...` | Full execution command line | Reveals encoded payloads, web requests, and evasion switches. |
| `CurrentDirectory` | String | `C:\Users\Public\Downloads\` | Working directory of process | Detects execution from writable user directories (`AppData`, `Temp`, `Public`). |
| `User` | String | `CYBERION\svc_backup` | User context under which binary executes | Pinpoints service account abuse or privilege elevation. |
| `Hashes` | String | `SHA256=A3B8C1...MD5=4D9E...` | Cryptographic hashes of the binary | Directly matchable against threat intelligence IOC databases. |
| `ParentProcessId` | Integer | `1024` | PID of creator process | Essential for tracing root cause and command propagation. |
| `ParentImage` | String | `C:\Windows\System32\wsmprovhost.exe` | Executable path of creator process | Flags anomalous execution chains (e.g. WMI/WinRM spawning `cmd.exe`). |
| `ParentCommandLine` | String | `wsmprovhost.exe -Embedding` | Full arguments of creator process | Distinguishes human administrative actions from automated remote exploitation. |
| `GrantedAccess` | Hex / String | `0x1010`, `0x1FFFFF` | Bitmask permissions requested during process handle opening | In Event ID 10: `0x1010` (`PROCESS_QUERY_LIMITED_INFORMATION` + `PROCESS_VM_READ`) or `0x1FFFFF` (`PROCESS_ALL_ACCESS`) on `lsass.exe` confirms credential dumping tools (Mimikatz, ProcDump, Nanodump). |
| `CallTrace` | String | `C:\Windows\SYSTEM32\ntdll.dll+9fb84...` | Stack trace of API call leading to access | Differentiates legitimate security agents (signed antivirus) from unbacked DLLs or reflective loaders. |
| `SourceImage` | String | `C:\Users\JohnDoe\AppData\Local\Temp\rundll32.exe` | Binary initiating the access or thread injection | Pinpoints injecting or dumping process. |
| `TargetImage` | String | `C:\Windows\System32\lsass.exe` | Target process receiving handle or remote thread | Critical anchor for memory-scraping detections. |
| `TargetFilename` | String | `C:\Users\Public\mimikatz.log` | Destination file written in Event ID 11 | Tracks dropped payloads, staged archives, and exfiltration staging. |
| `TargetObject` | String | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater` | Registry path written in Event ID 13 | Detects autostart persistence mechanisms. |

---

## 4. Zeek Network Telemetry

Zeek is an open-source, passive network traffic analyzer that converts raw packet streams into structured, protocol-specific audit records. It provides high-fidelity visibility into network communications independent of endpoint agent status.

### 4.1 Primary Zeek Logs in Scope

| Log Name | Monitored Protocol | Forensic Purpose | ATT&CK Mapping |
|:---|:---|:---|:---|
| `conn.log` | TCP, UDP, ICMP | Connection duration, byte counts, TCP flags, state tracking | T1071, T1048, T1090 |
| `dns.log` | DNS (UDP/TCP 53) | Query names, answer records, TTLs, record types | T1071.004, T1568, T1048 |
| `http.log` | HTTP (TCP 80/8080) | Request methods, URIs, User-Agents, status codes, payload sizes | T1071.001, T1105 |
| `ssl.log` | TLS / SSL (TCP 443) | SNI, TLS versions, JA3/JA3S cryptographic fingerprints, cert details | T1071.001, T1573 |

### 4.2 Zeek Field Definitions & Detection Relevance

| Field Name | Data Type | Example Value | Description | Detection Relevance |
|:---|:---|:---|:---|:---|
| `ts` | Float / Timestamp | `1728399721.492` | UNIX epoch timestamp with microsecond resolution | Temporal alignment and inter-arrival beaconing calculations. |
| `uid` | String | `Chq8262w8e411b9v8e` | Unique alphanumeric connection identifier | Joins across log files (e.g. joining `conn.log` with `http.log` or `ssl.log`). |
| `id.orig_h` | IP Address | `192.168.10.115` | Originating (client) IP address | Tracks internal infected endpoint. |
| `id.orig_p` | Port | `52410` | Originating client port | Identifies ephemeral source ports. |
| `id.resp_h` | IP Address | `185.106.94.234` | Destination (server) IP address | Correlates against threat intelligence reputation feeds, geo-IP, and ASN data. |
| `id.resp_p` | Port | `8443` | Destination service port | Flags non-standard ports used for C2 egress (e.g., HTTPS over 8443 or HTTP over 8080). |
| `proto` | String | `tcp` | Transport layer protocol | Distinguishes UDP/TCP flows. |
| `service` | String | `ssl`, `http`, `dns` | Application protocol inferred via protocol sniffing | Flags protocol mismatches (e.g., HTTP payload over port 443). |
| `duration` | Float | `3600.41` | Total connection lifespan in seconds | Identifies persistent interactive C2 reverse shells. |
| `orig_bytes` | Integer | `412` | Bytes sent from client to server | Used in ratio metrics (`orig_bytes / resp_bytes`) to identify exfiltration vs. download. |
| `resp_bytes` | Integer | `8492014` | Bytes returned from server to client | Distinguishes bulk tool transfer from small command pulses. |
| `conn_state` | String | `SF`, `S0`, `REJ` | State of TCP connection | `S0` flags failed scans; `SF` indicates normal completion; `RSTO` indicates abnormal teardown. |
| `query` | String | `aW5maWx0cmF0aW9u.tunnel.c2domain.com` | DNS query string requested | Detects base64/hex-encoded subdomains characteristic of DNS tunneling (T1071.004). |
| `qtype_name` | String | `TXT`, `A`, `AAAA` | DNS resource record type | Detects high volumes of TXT/NULL queries used for C2 payloads. |
| `answers` | List[String] | `["185.106.94.234"]` | Resolved IP or payload string | Identifies dynamic DNS, fast-flux, or base64 staging strings in TXT answers. |
| `host` | String | `185.106.94.234:8080` | HTTP Host header | Flags missing or raw-IP Host headers indicative of automated C2 clients. |
| `uri` | String | `/api/v1/heartbeat.php` | HTTP request path and query string | Matches known C2 framework malleable profiles (Cobalt Strike, Sliver, Mythic). |
| `user_agent` | String | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)...` | User-Agent string sent by client | Detects outdated, malformed, or blank User-Agents (e.g. `curl/7.88`, `Python-urllib`). |
| `status_code` | Integer | `200` | HTTP response code returned by server | Distinguishes alive C2 servers from expired redirectors. |
| `server_name` | String | `secure-login-portal.com` | TLS Server Name Indication (SNI) | Detects domain fronting, spoofed infrastructure, or newly registered domains. |
| `ja3` | String (MD5) | `72c589327861c8052f36449d00fb7dae` | TLS client hello cryptographic fingerprint | Pinpoints specific client tools (e.g., PowerShell, Cobalt Strike beacon, Metasploit) regardless of SNI or port. |
| `ja3s` | String (MD5) | `15af977ce25de4d75ebfb4702281a432` | TLS server hello cryptographic fingerprint | Detects known threat-actor C2 listener TLS configurations. |

---

## 5. Telemetry Normalization & Mapping Matrix

| Telemetry Dimension | Windows Security (EVTX) | Microsoft Sysmon | Zeek Network Monitor | Harmonized Sigma Field Target |
|:---|:---|:---|:---|:---|
| **Process Binary** | `ProcessName`, `NewProcessName` | `Image` | N/A (Endpoint only) | `Image` |
| **Process Args** | `CommandLine` | `CommandLine` | N/A (Endpoint only) | `CommandLine` |
| **Parent Binary** | `ParentProcessName` | `ParentImage` | N/A (Endpoint only) | `ParentImage` |
| **Target User** | `TargetUserName` | `User` | N/A | `User` |
| **Source IP** | `IpAddress` | `SourceIp` | `id.orig_h` | `SourceIp` / `c-ip` |
| **Destination IP** | N/A | `DestinationIp` | `id.resp_h` | `DestinationIp` / `cs-ip` |
| **Destination Port**| N/A | `DestinationPort` | `id.resp_p` | `DestinationPort` / `cs-port` |
| **DNS Query** | N/A | `QueryName` (Sysmon 22) | `query` (dns.log) | `query` / `QueryName` |
| **HTTP URI** | N/A | N/A | `uri` (http.log) | `cs-uri-stem` / `uri` |
| **Service Name** | `ServiceName` | N/A | N/A | `ServiceName` |
| **Target Memory** | N/A | `TargetImage`, `GrantedAccess` | N/A | `TargetImage`, `GrantedAccess` |

---
*Signed by:*  
**Detection Engineering & Threat Intelligence Practice, Cyberion Defense Labs**
