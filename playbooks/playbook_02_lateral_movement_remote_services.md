# Incident Response Playbook: Lateral Movement via Remote Services
**Playbook Reference:** CDL-IRP-02  
**Category:** Host & Network Intrusion Response  
**ATT&CK Techniques:** T1021.002 (SMB/Admin Shares), T1047 (WMI), T1569.002 (Service Execution: PsExec), T1021.001 (RDP)  
**Target Roles:** SOC Analysts (Tier 2/Tier 3), Endpoint Forensics Engineers, Network Engineers  
**Version:** 2.0  
**Last Updated:** 2026-10-08

---

## 1. Trigger Conditions & Alert Indicators

This playbook is activated upon any of the following triggers:
- **SIEM Alert:** Detection rule `CDL-RULE-003` (PsExec service installation or execution of `PSEXESVC.exe`).
- **SIEM Alert:** Detection rule `CDL-RULE-004` (WMI remote process creation via `wmiprvse.exe` spawning shells).
- **Correlation Alert:** `CDL-RULE-017` (Domain reconnaissance immediately followed by remote service invocation within 10 minutes).
- **Windows System Event 7045:** New service installed remotely with executable path pointing to `ADMIN$` or `C$\Windows\Temp`.
- **Anomalous Network Session:** Spike in SMB (TCP 445), WinRM (TCP 5985/5986), or RPC (TCP 135) sessions originating from an end-user workstation targeting member servers.

---

## 2. Phase 1: Investigation & Blast-Radius Scoping

```
[ Step 1.1: Map the Infection Graph ]
   ├── Identify the Pivoting Source Host (IP_source, Host_source).
   ├── Identify the Target Destination Host(s) (IP_dest, Host_dest).
   └── Extract the User Account initiating the network connection.

[ Step 1.2: Correlate Lateral Movement Mechanism ]
   ├── SMB / Admin Share: Check Windows Event 5140/5145 for ADMIN$ or IPC$ access.
   ├── PsExec / Service Exec: Check Windows System Event 7045 and Sysmon 1 for service binary name.
   ├── WMI Execution: Check Sysmon Event 1 for wmiprvse.exe spawning cmd.exe / powershell.exe.
   └── WinRM Execution: Check Sysmon Event 1 for wsmprovhost.exe spawning command shells.

[ Step 1.3: Retrospective Host Tracing ]
   ├── Work backwards from IP_source: query who logged onto IP_source before the lateral hop.
   └── Check for credential dumping alerts (CDL-RULE-002 LSASS access) on IP_source.
```

---

## 3. Phase 2: Containment Procedures (Target Time: < 20 Minutes)

1. **Dual-Endpoint Isolation:**
   - Simultaneously network-isolate **BOTH** the source workstation and all touched target destination machines using EDR client containment:
   ```powershell
   # EDR CLI / API containment action:
   Invoke-EDRHostIsolation -ComputerName "WKSTN-SOURCE-01", "WKSTN-TARGET-02"
   ```
2. **Internal Perimeter Micro-Segmentation:**
   - If lateral movement is detected spreading across subnets, implement temporary internal firewall drops on ports:
     - `TCP 445` (SMB)
     - `TCP 135` (RPC Endpoint Mapper)
     - `TCP 5985/5986` (WinRM)
     - `TCP 3389` (RDP)
   - Ensure exceptions remain active only for dedicated Privileged Access Workstations (PAWs).
3. **Disable Pivoting Account:**
   - Immediately suspend the Active Directory user account utilized for the remote connection:
   ```powershell
   Disable-ADAccount -Identity "compromised_admin"
   ```

---

## 4. Phase 3: Eradication & Forensic Cleaning

1. **Service and Process Termination:**
   - Terminate offending remote processes on destination hosts:
   ```cmd
   taskkill /F /IM PSEXESVC.exe
   taskkill /F /IM cmd.exe
   ```
   - Delete rogue service entries from the Windows Service Control Manager:
   ```cmd
   sc.exe delete PSEXESVC
   ```
2. **File System Remediation:**
   - Purge dropped staging binaries located in admin shares:
     - `C:\Windows\PSEXESVC.exe`
     - `C:\Windows\Temp\*`
     - `C:\Users\Public\*`
3. **Audit High-Privileged AD Groups:**
   - Verify no new members were injected into `Domain Admins`, `Enterprise Admins`, or `Backup Operators` during the lateral window (`CDL-RULE-007`).
4. **Memory Dump Acquisition:**
   - Prior to system rebuild, acquire full memory dumps from the source and destination hosts for forensic artifact preservation:
   ```powershell
   winpmem.exe -o C:\Forensics\WKSTN-SOURCE-01.raw
   ```

---

## 5. Phase 4: Recovery & Post-Incident Verification

1. Rebuild or re-image the initial compromised source host from known-good baseline images.
2. Member servers subject to lateral access must undergo thorough integrity verification (System File Checker `sfc /scannow`, Antivirus full scan, and local administrator password randomization via LAPS).
3. Confirm LAPS (Local Administrator Password Solution) is deployed and functioning across 100% of domain workstations so no shared local admin passwords exist.

---

## 6. Stakeholder Communications Matrix

| Stakeholder | Timing | Communication Method | Key Information |
|:---|:---|:---|:---|
| **SOC Shift Lead** | Immediate (<5 min) | War Room Voice Bridge | Source host, destination hosts, lateral vector (SMB/WMI), containment action. |
| **Infrastructure / Server Team** | Within 15 minutes | Priority Ticket / Slack `#sec-ops` | Member server names impacted, temporary firewall ACL restrictions on port 445. |
| **Incident Commander** | Within 20 minutes | Incident Summary Portal | Number of hosts in blast radius, account compromised, containment verified. |
| **Client Primary Contact** | Within 30 minutes | Encrypted Notification | Scope of lateral movement, confirmation of host quarantine, business impact. |

---
*Authorized by:*  
**Cyberion Incident Response Practice**
