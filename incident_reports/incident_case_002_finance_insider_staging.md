# Incident Investigation Case Report: Compromised Backup Service & Active Directory Database Staging
**Case Reference:** INC-2026-0894  
**Severity:** P2 — HIGH  
**Lead Investigator:** Detection Engineering & Incident Response Practice  
**Date Opened:** 2026-10-07 03:00 UTC  
**Date Closed:** 2026-10-07 11:45 UTC  
**Closure Classification:** **TRUE POSITIVE (Privilege Abuse & Data Staging)**  
**Associated Threat Hunt:** [`CDL-HUNT-02`](file:///c:/Users/Hp/Desktop/cyber/threat_hunts/hunt_02_lolbins_wmi_reconnaissance.md)  
**Applicable Playbooks:** [`playbook_01_compromised_credentials.md`](file:///c:/Users/Hp/Desktop/cyber/playbooks/playbook_01_compromised_credentials.md), [`playbook_02_lateral_movement_remote_services.md`](file:///c:/Users/Hp/Desktop/cyber/playbooks/playbook_02_lateral_movement_remote_services.md)

---

## 1. Executive Summary
On 2026-10-07 at 03:00 UTC, threat hunt CDL-HUNT-02 identified anomalous execution of Living-Off-The-Land discovery binaries on finance workstation `WS-FIN-04` (`192.168.10.142`) executing under service account `CYBERION\svc_backup`. Within 25 minutes of the initial hunt flag, detection rule `CDL-RULE-006` triggered on member server `FS-CORP-01`, detecting the invocation of `vssadmin.exe` creating volume shadow copies and copying `ntds.dit`.

Investigation revealed that an external threat actor leveraged compromised service account credentials originating from marketing host `WS-MKTG-02` via WinRM, conducted host discovery, hopped to the corporate file server hosting domain database backups, extracted a shadow copy of `ntds.dit` along with the `SYSTEM` registry hive, and attempted to compress and stage the database for DNS tunneling exfiltration. The intrusion was interrupted before the exfiltration payload left the corporate network.

---

## 2. Reconstructed Incident Timeline (Raw Log Evidence)

| Timestamp (UTC) | Sensor Source | Event ID | Entity / Host | Account | Raw Log Evidence & Technical Detail |
|:---|:---|:---:|:---|:---|:---|
| `2026-10-07 02:15:02` | Win Security | `4624` | `WS-FIN-04` | `CYBERION\svc_backup` | **T1078.002 Initial Logon:** LogonType 3 (Network Logon) from source workstation `192.168.10.88` (`WS-MKTG-02`) via WinRM port 5985. |
| `2026-10-07 02:18:22` | Sysmon | `1` | `WS-FIN-04` | `CYBERION\svc_backup` | **T1082 / T1016 Discovery:** `wsmprovhost.exe` spawns `cmd.exe`, which executes `whoami /priv`, `systeminfo`, and `nltest /domain_trusts` (*Flagged by CDL-HUNT-02*). |
| `2026-10-07 02:24:18` | Win Security | `4624` | `FS-CORP-01` | `CYBERION\svc_backup` | **T1021.002 Lateral Movement:** Network logon to File Server `FS-CORP-01` (`192.168.20.15`) using `svc_backup` administrative privileges. |
| `2026-10-07 02:26:05` | Sysmon | `1` | `FS-CORP-01` | `CYBERION\svc_backup` | **T1003.003 Credential Access:** Command executed: `vssadmin.exe create shadow /for=C:` (*Triggered CDL-RULE-006*). Output: Shadow Copy Volume `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3` created. |
| `2026-10-07 02:27:12` | Sysmon | `1` | `FS-CORP-01` | `CYBERION\svc_backup` | **T1003.003 Database Copy:** Command executed: `cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\NTDS\ntds.dit C:\Users\Public\ntds.dit`. |
| `2026-10-07 02:27:45` | Sysmon | `1` | `FS-CORP-01` | `CYBERION\svc_backup` | **T1003.003 Hive Save:** Command executed: `reg.exe save HKLM\SYSTEM C:\Users\Public\system.hiv`. |
| `2026-10-07 02:31:10` | Sysmon | `11` | `FS-CORP-01` | `CYBERION\svc_backup` | **T1560.001 Archive Collected Data:** File created: `C:\Users\Public\backup_stage.7z` (Compressed archive containing `ntds.dit` and `system.hiv` with password protection). |
| `2026-10-07 02:35:18` | Zeek `dns` | N/A | `192.168.20.15` | N/A | **T1071.004 Staging Query:** DNS query for `stage01.tunnel.data-exfil-c2.net` type TXT (*Flagged by CDL-RULE-011*). |
| `2026-10-07 02:38:00` | Security Ops | N/A | Multiple | SOC Team | **Containment Executed:** `FS-CORP-01` and `WS-FIN-04` network-isolated. Account `svc_backup` disabled. Staged archive deleted. |

---

## 3. Root Cause Analysis (5-Whys Methodology)

```
1. Why was the attacker able to access the AD database copy on FS-CORP-01?
   └── The account CYBERION\svc_backup had Full Control and Volume Shadow Copy creation privileges.

2. Why did svc_backup have interactive logon and excessive administrative rights?
   └── When the backup software was deployed 2 years ago, the vendor requested Domain Admin rights, and the account was never downgraded to least-privilege Backup Operators.

3. Why did the attacker possess the plaintext password for svc_backup?
   └── The password was hardcoded in an unencrypted batch script (backup_sync.bat) stored on a readable network share accessible to WS-MKTG-02.

4. How did the attacker access WS-MKTG-02?
   └── Initial phish on marketing employee allowing local user shell.

5. Why was an unencrypted script containing domain service credentials on a general share?
   └── ROOT CAUSE: Lack of credential scanning policies on internal shares, absent Managed Service Account (gMSA) adoption, and unmonitored hardcoded password hygiene.
```

---

## 4. MITRE ATT&CK Mapping

```
Adversary Kill-Chain:
[Valid Accounts: T1078.002] Compromised Backup Service Principal
         │
         ▼
[Discovery: T1082 / T1016] LOLBAS System and Trust Queries (WS-FIN-04)
         │
         ▼
[Lateral Movement: T1021.002] Remote Administration via WinRM to File Server
         │
         ▼
[Credential Access: T1003.003] VSS Shadow Copy Extraction of NTDS.dit & SYSTEM Hive
         │
         ▼
[Collection: T1560.001] Data Encrypted and Compressed in 7-Zip Archive
         │
         ▼
[Command & Control: T1071.004] DNS TXT Record Tunneling Beacon Probe
```

---

## 5. Impact Assessment

- **Confidentiality:** HIGH. Active Directory database (`ntds.dit`) containing all domain account password hashes and the decrypting `SYSTEM` hive were copied to disk; however, containment occurred prior to network exfiltration completion.
- **Integrity:** LOW. No domain data was altered; shadow copies were created and staged files deleted.
- **Availability:** LOW. File server remained operational throughout.
- **Scope of Affected Assets:**
  - `WS-MKTG-02` (`192.168.10.88`): Originating compromised workstation.
  - `WS-FIN-04` (`192.168.10.142`): Discovery pivot host.
  - `FS-CORP-01` (`192.168.20.15`): Member server with staged database.

---

## 6. Containment, Eradication & Recovery Actions

1. **Immediate Quarantine:**
   - Isolated `WS-MKTG-02`, `WS-FIN-04`, and `FS-CORP-01` via EDR firewall containment.
   - Disabled Active Directory account `CYBERION\svc_backup`.
2. **Artifact Eradication:**
   - Deleted staged files: `C:\Users\Public\ntds.dit`, `C:\Users\Public\system.hiv`, `C:\Users\Public\backup_stage.7z`.
   - Executed `vssadmin delete shadows /for=C: /shadow=...` to remove unauthorized shadow copy volume.
   - Purged batch script containing cleartext credentials from network share.
3. **Identity Security Actions:**
   - Migrated backup infrastructure to Group Managed Service Accounts (gMSA), eliminating static passwords.
   - Restricted backup accounts to specific Backup Operator rights with logon denial on standard workstations.
   - Triggered corporate-wide credential rotation as a precautionary measure.

---

## 7. Closure Classification & Justification

- **Closure Classification:** **TRUE POSITIVE (P2 - High Severity)**
  - *Justification:* Verified extraction of critical security credentials (`ntds.dit`), confirmed unauthorized lateral WinRM hop from unapproved marketing host, and observed anomalous DNS exfiltration preparation.

---
*Approved for Closure by:*  
**Director, Security Operations — Cyberion Defense Labs**
