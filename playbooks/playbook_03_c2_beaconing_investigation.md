# Incident Response Playbook: Command & Control (C2) Beaconing
**Playbook Reference:** CDL-IRP-03  
**Category:** Network & Endpoint Command & Control Response  
**ATT&CK Techniques:** T1071.001 (Web Protocols: HTTP/S), T1071.004 (DNS Tunneling), T1572 (Protocol Tunneling), T1573 (Encrypted C2)  
**Target Roles:** SOC Analysts (Tier 2/Tier 3), Threat Hunters, Network Security Engineers  
**Version:** 2.0  
**Last Updated:** 2026-10-08

---

## 1. Trigger Conditions & Alert Indicators

This playbook is activated upon any of the following triggers:
- **SIEM Alert:** Detection rule `CDL-RULE-005` (Suspicious HTTP C2 beaconing URI or anomalous User-Agent).
- **SIEM Alert:** Detection rule `CDL-RULE-011` (DNS TXT record tunneling or long high-entropy domain queries).
- **Correlation Alert:** `CDL-RULE-018` (LSASS memory dump followed by anomalous outbound network egress within 3 minutes).
- **Threat Hunt Finding:** Jitter-bounded connection patterns surfaced via analytics (e.g. `CDL-HUNT-01`).
- **Threat Intel Match:** Outbound traffic matching active C2 IP addresses, malicious domains, or JA3 hashes documented in Cyberion Threat Intelligence feeds.

---

## 2. Phase 1: Investigation & Technical Triage

```
[ Step 1.1: Triage Network Telemetry ]
   ├── Query Zeek conn.log / http.log / ssl.log for the target external IP/Domain.
   ├── Measure connection frequency: calculate total connections, mean interval, and jitter ratio.
   ├── Analyze HTTP parameters: check HTTP Host header, User-Agent, URI structure, and response codes.
   └── Inspect TLS parameters: extract Server Name Indication (SNI), JA3/JA3S fingerprints, and cert validity.

[ Step 1.2: Identify Originating Endpoint Process ]
   ├── Query Sysmon Event ID 3 (Network Connection) on the internal IP:
   │     SELECT Image, ProcessId, DestinationIp, DestinationPort, User
   ├── Determine if the binary is a standard browser (chrome.exe) or LOLBAS/stager (rundll32.exe, powershell.exe).
   └── If browser, verify if parent process is suspicious or if DLL injection occurred (Sysmon 8 / 10).

[ Step 1.3: Analyze Payload Directionality & Volume ]
   ├── Compare orig_bytes (outbound) to resp_bytes (inbound).
   ├── High orig_bytes indicates active data exfiltration; small periodic orig_bytes indicates interactive heartbeat.
   └── Check for DNS tunneling: audit Zeek dns.log for burst volumes of TXT/NULL query types.
```

---

## 3. Phase 2: Containment Procedures (Target Time: < 15 Minutes)

1. **Perimeter Firewall Null-Route / Egress Block:**
   - Immediately push emergency block rules to corporate border firewalls and cloud secure web gateways (SWG):
   ```bash
   # Edge Firewall / Palo Alto / Fortinet CLI:
   fw-admin rule insert top "EMERGENCY_C2_BLOCK" --src any --dst <C2_IP> --action DROP --log
   # DNS Sinkholing:
   dns-server redirect domain "<malicious_domain>" to 127.0.0.1
   ```
2. **Endpoint Network Quarantine:**
   - Execute network containment on the beaconing host via EDR agent:
   ```powershell
   Invoke-EDRIsolateHost -EndpointId "<Host_GUID>"
   ```
3. **Terminate Offending Process & Sever Socket:**
   - Immediately kill the offending PID:
   ```cmd
   taskkill /PID <beacon_pid> /F
   ```
4. **Proxy Session Teardown:**
   - Clear established sessions and persistent TCP keep-alives at the outbound proxy layer.

---

## 4. Phase 3: Eradication & Forensic Deep Dive

1. **Memory Dump Capture:**
   - Prior to rebooting the machine, dump the memory of the beaconing process to extract in-memory configuration blocks (e.g. Cobalt Strike malleable C2 profile, public keys, fallback domains):
   ```powershell
   procdump.exe -ma <beacon_pid> C:\Forensics\beacon_dump.dmp
   ```
2. **Scan for Secondary Fallback Beacons:**
   - Query DNS logs (`dns.log`) for recently queried domains around the initial execution window to detect dormant fallback C2 channels (backup domains or dead-drop resolvers).
3. **Identify Ingress Persistence:**
   - Check persistence locations on the machine:
     - Registry Run keys (`CDL-RULE-010`)
     - Scheduled Tasks (`CDL-RULE-009`)
     - Startup folder shortcuts (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`)
     - WMI Event Consumers (`Get-WmiObject -Namespace root\subscription -Class __EventConsumer`)
4. **Payload Purge & Reimage:**
   - Remove binary artifacts from temporary directories (`%TEMP%`, `C:\Users\Public`).
   - If root-level injection was observed, schedule full workstation re-imaging.

---

## 5. Phase 4: Recovery & Post-Incident Verification

1. Verify perimeter sensor telemetry: confirm zero outbound connection attempts to the C2 infrastructure across all corporate subnets.
2. Ingest all extracted IOCs (IPs, domains, hashes, JA3 fingerprints) into SIEM threat intelligence lookup tables with automated 90-day alert generation.
3. Conduct retrospectives on network boundary controls: evaluate why non-standard outbound ports (e.g. 8443, 8080) were permitted egress without TLS inspection.

---

## 6. Stakeholder Communications Matrix

| Stakeholder | Timing | Channel | Deliverable / Key Information |
|:---|:---|:---|:---|
| **Incident Commander** | Within 5 minutes | Secure Voice Call / Signal | Host identity, external C2 IP/domain, initial data volume assessment. |
| **Network Security Team** | Immediate (<10 min) | Secure Chat / Ticket | Emergency IP blocklist and DNS sinkhole request. |
| **Threat Intelligence Lead**| Within 30 minutes | Ticket / STIX Report | C2 indicators, malleable profile parameters, JA3 hashes for external attribution. |
| **Executive Management** | Within 1 hour | Executive Incident Status | Confirmation of perimeter severance, containment status, exfiltration assessment. |

---
*Authorized by:*  
**Cyberion Incident Response Practice**
