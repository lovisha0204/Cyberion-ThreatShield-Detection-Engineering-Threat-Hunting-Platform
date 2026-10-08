# Threat Hunt Report: Silent LOLBAS & Host Reconnaissance
**Hunt Reference:** CDL-HUNT-02  
**Technique Mapped:** T1082 (System Information Discovery) & T1016 (System Network Configuration Discovery)  
*(Note: Uncovered Technique Track — not currently alerted by standard detection rules)*  
**Lead Threat Hunter:** Cyberion Detection Engineering Practice  
**Date Executed:** 2026-10-08  
**Status / Outcome:** **CONFIRMED FINDING (Escalated to Incident Response)**  
**Escalation Target:** Case [`INC-2026-0894`](file:///c:/Users/Hp/Desktop/cyber/incident_reports/incident_case_002_finance_insider_staging.md)

---

## 1. Threat Intelligence & Rationale

Adversaries who gain initial access frequently avoid dropping proprietary reconnaissance tools to minimize disk artifacts. Instead, they rely on native Windows Living-Off-The-Land Binaries (LOLBAS) — such as `systeminfo.exe`, `nltest.exe`, `whoami.exe`, `net.exe`, `ipconfig.exe`, and `tasklist.exe` — to map domain trust relationships, local privileges, and security software. 

Because system administrators also invoke these binaries occasionally, static single-event alerting on `whoami.exe` or `systeminfo.exe` yields unacceptable false-positive volumes in large SOCs. This threat hunt utilized **burst-window clustering** and **process lineage rarity modeling** to differentiate benign administrative tasks from adversary discovery phases.

---

## 2. Hunt Hypothesis

> **Hypothesis:** An adversary or compromised internal principal is actively conducting host and network situational awareness queries on endpoints by executing three or more distinct built-in reconnaissance utilities within a 3-minute burst window, originating from non-interactive parent processes or standard user accounts outside of IT administration.

---

## 3. Data Sources & Query Methodology

### 3.1 Telemetry Scope
- **Endpoint Telemetry:** Sysmon Event ID 1 (Process Creation) and Windows Security Event ID 4688.
- **Scope:** All corporate member servers and financial department workstations.
- **Timeframe:** 7-day retrospective log repository.

### 3.2 Analytical Approach & Query Syntax

The hunt evaluated clusters of reconnaissance tool executions grouped by host and user, calculating execution cardinality within tumbling 180-second windows.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\systeminfo.exe" OR Image="*\\whoami.exe" OR Image="*\\nltest.exe" 
 OR Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\ipconfig.exe" 
 OR Image="*\\tasklist.exe" OR Image="*\\route.exe" OR Image="*\\quser.exe")
| bin _time span=3m
| stats dc(Image) as unique_recon_tools, values(Image) as tools_used, 
        values(CommandLine) as commands, values(ParentImage) as parent_processes,
        count as total_executions 
  by _time, ComputerName, User
| where unique_recon_tools >= 3
| sort - unique_recon_tools
```

### 3.3 Negative Result Filter & Baseline Elimination
- Eliminated approved IT deployment scripts: filtered out SCCM service account (`CYBERION\svc_sccm`) executing inventory cycles.
- Eliminated automated logon scripts running exclusively at user startup (`C:\Windows\System32\userinit.exe`).

---

## 4. Empirical Findings & Observations

### 4.1 Identified Activity Cluster

The analysis isolated an acute reconnaissance sequence on host `WS-FIN-04` (`192.168.10.142`) occurring at `2026-10-07 02:18:22 UTC` (outside normal corporate operating hours):

| Timestamp (UTC) | Host | User Context | Executable | Full Command Line | Parent Process |
|:---|:---|:---|:---|:---|:---|
| `2026-10-07 02:18:22` | `WS-FIN-04` | `CYBERION\svc_backup` | `whoami.exe` | `whoami /priv` | `C:\Windows\System32\cmd.exe` |
| `2026-10-07 02:18:35` | `WS-FIN-04` | `CYBERION\svc_backup` | `systeminfo.exe` | `systeminfo` | `C:\Windows\System32\cmd.exe` |
| `2026-10-07 02:18:49` | `WS-FIN-04` | `CYBERION\svc_backup` | `nltest.exe` | `nltest /domain_trusts /all_trusts` | `C:\Windows\System32\cmd.exe` |
| `2026-10-07 02:19:04` | `WS-FIN-04` | `CYBERION\svc_backup` | `net.exe` | `net group "Domain Admins" /domain` | `C:\Windows\System32\cmd.exe` |
| `2026-10-07 02:19:28` | `WS-FIN-04` | `CYBERION\svc_backup` | `tasklist.exe` | `tasklist /v /fo csv` | `C:\Windows\System32\cmd.exe` |

*Critical Anomalies:*
1. **User Identity:** The commands were executed by service account `svc_backup`. Service accounts are designed for headless scheduled backup tasks and should never run interactive command-line sessions.
2. **Timing:** Executed at 02:18 UTC without any scheduled task reference.
3. **Execution Depth:** Querying domain trusts (`nltest /domain_trusts`) and enumerating Domain Admins confirmed targeted active directory discovery.

### 4.2 Parent Process Forensics
Inspecting the parent of `cmd.exe` (PID: 7120) revealed:
- **Parent Image:** `C:\Windows\System32\wsmprovhost.exe` (WinRM Host Process).
- **Logon Type:** Windows Event ID 4624 (LogonType 3 - Network Logon) authenticated from source IP `192.168.10.88` (`WS-MKTG-02`).
- This confirmed unauthorized lateral access via WinRM using stolen backup service credentials.

---

## 5. Conclusion & Actionable Next Steps

- **Conclusion:** **CONFIRMED ACTIVE THREAT.** The hypothesis identified an active credential compromise and unauthorized domain discovery session on `WS-FIN-04`.
- **Incident Escalation:** Escalated immediately to Incident Response under Case ID **`INC-2026-0894`**.
- **Detection Content Feedback:**
  - Designed Correlation Rule `CDL-RULE-017` (Recon to Lateral Movement).
  - Drafted a behavior-based Sigma rule for interactive command execution under headless service accounts.

---
*Signed by:*  
**Lead Threat Hunter, Cyberion Defense Labs**
