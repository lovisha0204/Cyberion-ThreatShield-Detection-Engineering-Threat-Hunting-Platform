# Cyberion Defense Labs — Detection Rule Catalog
**Document ID:** CDL-RULE-CATALOG-01  
**Classification:** Internal Use — Engineering Program  
**Author:** Detection Engineering & Threat Intelligence Practice  
**Date:** 2026-10-08  
**Rules Total:** 18 Production-Grade Sigma Rules (15 Single-Source + 3 Correlation Rules)

---

## 1. Rule Library Summary Matrix

| Rule ID | File Name | ATT&CK ID | MITRE Technique | Tactic | Log Source | Severity | Rule Type |
|:---|:---|:---|:---|:---|:---|:---|:---|
| **CDL-RULE-001** | `CDL-RULE-001_powershell_download_cradle.yml` | `T1059.001` | PowerShell Download Cradles | Execution | Windows Process Creation | High | Standard |
| **CDL-RULE-002** | `CDL-RULE-002_mimikatz_lsass_dump.yml` | `T1003.001` | LSASS Memory Dumping | Credential Access | Sysmon ProcessAccess | Critical | Standard |
| **CDL-RULE-003** | `CDL-RULE-003_psexec_service_installation.yml` | `T1569.002` / `T1021.002` | PsExec Service Installation | Lateral Movement | Windows Process Creation | High | Standard |
| **CDL-RULE-004** | `CDL-RULE-004_wmi_process_creation.yml` | `T1047` | WMI Process Creation | Execution | Windows Process Creation | High | Standard |
| **CDL-RULE-005** | `CDL-RULE-005_c2_periodic_beaconing_http.yml` | `T1071.001` | C2 HTTP Periodic Beaconing | Command & Control | Zeek HTTP / Proxy | High | Standard |
| **CDL-RULE-006** | `CDL-RULE-006_ntds_dit_volume_shadow_copy.yml` | `T1003.003` | NTDS.dit Shadow Copy Extraction | Credential Access | Windows Process Creation | Critical | Standard |
| **CDL-RULE-007** | `CDL-RULE-007_user_added_to_domain_admins.yml` | `T1098` / `T1078.002` | Privileged Group Addition | Persistence / PrivEsc | Windows Security (4728/4732) | High | Standard |
| **CDL-RULE-008** | `CDL-RULE-008_suspicious_rundll32_execution.yml` | `T1218.011` | Rundll32 Execution from Writable Paths | Defense Evasion | Windows Process Creation | Medium | Standard |
| **CDL-RULE-009** | `CDL-RULE-009_scheduled_task_creation_schtasks.yml` | `T1053.005` | Scheduled Task Persistence | Persistence | Windows Process Creation | Medium | Standard |
| **CDL-RULE-010** | `CDL-RULE-010_reg_run_key_persistence.yml` | `T1547.001` | Registry Run Key Persistence | Persistence | Sysmon RegistryEvent (13) | Medium | Standard |
| **CDL-RULE-011** | `CDL-RULE-011_dns_txt_record_exfiltration.yml` | `T1071.004` / `T1048` | DNS TXT Record Tunneling | C2 / Exfiltration | Zeek DNS / Sysmon 22 | High | Standard |
| **CDL-RULE-012** | `CDL-RULE-012_suspicious_certutil_download.yml` | `T1105` / `T1218` | Ingress Tool Transfer (Certutil) | Command & Control | Windows Process Creation | High | Standard |
| **CDL-RULE-013** | `CDL-RULE-013_mshta_obfuscated_vbs.yml` | `T1218.005` | Defense Evasion via Mshta | Defense Evasion | Windows Process Creation | High | Standard |
| **CDL-RULE-014** | `CDL-RULE-014_remote_desktop_tunneling.yml` | `T1021.001` / `T1572` | RDP Port Tunneling via Netsh | Lateral Movement | Windows Process Creation | High | Standard |
| **CDL-RULE-015** | `CDL-RULE-015_kerberoasting_spn_request.yml` | `T1558.003` | Kerberoasting SPN Ticket Request | Credential Access | Windows Security (4769) | Medium | Standard |
| **CDL-RULE-016** | `CDL-RULE-016_correlation_brute_force_to_success.yml` | `T1110` + `T1078` | Brute Force to Successful Logon | Credential Access / Initial Access | Windows Security (4625 -> 4624) | High | **Correlation (Temporal)** |
| **CDL-RULE-017** | `CDL-RULE-017_correlation_recon_to_lateral_movement.yml` | `T1087` + `T1021.002` | Domain Recon to Lateral Movement | Discovery / Lateral Movement | Windows Process Creation Sequence | High | **Correlation (Sequence)** |
| **CDL-RULE-018** | `CDL-RULE-018_correlation_lsass_dump_to_c2_egress.yml` | `T1003.001` + `T1071.001` | LSASS Dump to Outbound Network Egress | Credential Access / C2 | Sysmon 10 -> Sysmon 3 / Zeek | Critical | **Correlation (Multi-Source)** |

---

## 2. Severity Classification Rationale

- **Critical:** Immediate risk of full enterprise or active directory domain compromise. Requires immediate containment, account suspension, and P1 escalation (e.g. LSASS dumping, NTDS.dit extraction, credential dumping followed by C2 egress).
- **High:** High-fidelity indicator of offensive tool execution, lateral movement, or active beaconing. Unlikely to be benign outside sanctioned IT administration windows.
- **Medium:** Suspicious living-off-the-land utility usage or persistence configuration that occurs occasionally in normal enterprise environments (e.g. scheduled tasks, registry run keys, rundll32 invocations). Requires correlation or tuning exclusions.
- **Low / Informational:** Baseline events and audit trails (e.g. single failed login) retained for correlation and threat hunting inquiries.

---
*Maintained by:*  
**Detection Engineering Practice, Cyberion Defense Labs**
