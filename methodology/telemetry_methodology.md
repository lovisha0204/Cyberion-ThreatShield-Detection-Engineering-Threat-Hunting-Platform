# Cyberion Defense Labs — Telemetry & Validation Methodology
**Document ID:** CDL-METH-01  
**Classification:** Internal Use — Engineering Program  
**Author:** Detection Engineering & Threat Intelligence Practice  
**Date:** 2026-10-08  
**Sprint:** 4-Week Detection Engineering Sprint (CDL-DET-V2)

---

## 1. Executive Summary & Purpose
This methodology document defines the architectural standards, log acquisition protocols, adversary emulation pipelines, and rule validation mechanisms employed by Cyberion Defense Labs. In compliance with the **CDL-DET-V2 PRD**, every detection rule, threat hunt, and incident investigation deliverable must be anchored in authentic, verifiable telemetry rather than speculative assumptions.

---

## 2. Public & Emulated Dataset Repositories

Cyberion Defense Labs leverages a hybrid data acquisition architecture combining four authoritative, publicly documented security telemetry sources:

```
+--------------------------------------------------------------------------------------------------+
|                                    CYBERION TELEMETRY ARCHITECTURE                              |
+--------------------------------------------------------------------------------------------------+
|                                                                                                  |
|   +-----------------------+   +-----------------------+   +----------------------------------+   |
|   |    Mordor Project     |   |   EVTX-ATTACK-SAMPLES |   |       Splunk BOTS v1 / v2        |   |
|   |  (OTRF Emulations)    |   |  (Technique-Specific) |   |    (Enterprise Attack Stream)    |   |
|   +-----------+-----------+   +-----------+-----------+   +-----------------+----------------+   |
|               |                           |                                 |                    |
|               +---------------------+     |     +---------------------------+                    |
|                                     |     |     |                                                |
|                                     v     v     v                                                |
|   +------------------------------------------------------------------------------------------+   |
|   |           Atomic Red Team (Lab Telemetry - Sysmon v15 + Win Security 2022)                |   |
|   +------------------------------------------------------------------------------------------+   |
|                                                  |                                               |
|                                                  v                                               |
|   +------------------------------------------------------------------------------------------+   |
|   |                   Cyberion Harmonization & Ingestion Engine (Python Harness)             |   |
|   +------------------------------------------------------------------------------------------+   |
|                     |                                                    |                       |
|                     v                                                    v                       |
|     [Positive Telemetry: Attack Sets]                    [Negative Telemetry: Benign Baseline]   |
|                     |                                                    |                       |
|                     +---------------------+------------------------------+                       |
|                                           |                                                      |
|                                           v                                                      |
|                          +----------------------------------+                                    |
|                          |   Detection Rule Engine (Sigma)  |                                    |
|                          +----------------------------------+                                    |
|                                           |                                                      |
|                     +---------------------+---------------------+                                |
|                     v                                           v                                |
|           [True Positive Alerts]                       [False Positive Alerts]                   |
|          (Mapped to MITRE ATT&CK)                     (Documented in Tuning Log)                 |
+--------------------------------------------------------------------------------------------------+
```

### 2.1 Selected Data Sources

1. **Mordor Project (Open Threat Research Forge)**
   - *Description:* Pre-recorded adversary emulation datasets capturing structured security events from orchestrated red-team campaigns (e.g. Cobalt Strike, Empire, APT29 / Cozy Bear).
   - *Telemetry Types:* Windows Event Logs (`Microsoft-Windows-Sysmon/Operational`, `Security.evtx`, `System.evtx`).
   - *Target Techniques:* T1059 (PowerShell / WMI), T1003 (OS Credential Dumping), T1021.002 (SMB/Windows Admin Shares), T1055 (Process Injection).

2. **EVTX-ATTACK-SAMPLES (Public Repository)**
   - *Description:* Highly granular, technique-isolated Windows Event Log samples capturing precise offensive tool invocations and evasion behaviors.
   - *Target Techniques:* T1569.002 (PsExec / Remote Service Creation), T1003.003 (NTDS.dit Shadow Copies), T1558.003 (Kerberoasting via RC4 Ticket Requests), T1218 (LOLBAS: Mshta, Rundll32, Certutil).

3. **Splunk Boss of the SOC (BOTS) Datasets (BOTS v1 & BOTS v2)**
   - *Description:* Multi-tier enterprise dataset simulating realistic corporate infrastructure (DNS, web proxy, active directory, perimeter firewalls) undergoing an advanced multi-stage attack.
   - *Target Telemetry:* Zeek network logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`), IIS web server logs, Windows Security Audit logs.
   - *Target Behaviors:* C2 periodic beaconing, lateral reconnaissance, web shell invocation, high-volume data staging.

4. **Atomic Red Team (Lab Generated Host Telemetry)**
   - *Description:* Repeatable adversary emulation test cases mapped strictly to MITRE ATT&CK, executed within an instrumented Windows Server 2022 / Windows 11 Enterprise sandbox environment equipped with Sysmon 15.0 and Enhanced Auditing policies.
   - *Instrumentation:* High-fidelity Sysmon configuration (SwiftOnSecurity baseline enhanced for LSASS access and DNS tracking).
   - *Validation Focus:* Generation of fresh baseline events and testing tuning exceptions against legitimate admin scripts (PowerShell modules, SCCM updates).

---

## 3. Log Ingestion, Normalization & Replay Pipeline

To guarantee deterministic, reproducible evaluations without depending on brittle external cloud services, Cyberion employs a structured log processing pipeline:

### 3.1 Extraction and Serialization
- Raw `.evtx` logs from samples and lab runs are extracted and converted to canonical JSON structures matching the Sigma event schema standard.
- Timestamps are normalized to ISO-8601 UTC format (`YYYY-MM-DDTHH:MM:SS.fffZ`) to maintain chronological sequencing across disparate sensor streams.
- Event attributes are structured into flat key-value representations reflecting production SIEM log formats (Windows Security event schemas and Sysmon operational event representations).

### 3.2 Dual-Track Dataset Architecture
To rigorously assess both detection sensitivity and specificity, the test pipeline feeds two distinct datasets:
1. **Attack Telemetry Corpus (`attack_telemetry.json`):** Contains positive event sequences that mirror observed adversary tactics, techniques, and procedures (TTPs), containing malicious executions, memory handles, registry injections, and network exfiltration requests.
2. **Benign Baseline Corpus (`benign_telemetry.json`):** Contains enterprise background noise, standard administrative activity (e.g., Google Chrome updates, NinjaRMM maintenance, legitimate backup jobs, standard Kerberos ticket requests), ensuring rules do not trigger alert floods in real SOC production environments.

---

## 4. Rule Quality & Testing Protocol

Every detection rule produced during this engagement must pass a three-stage validation protocol before being tagged as `production`:

```
 Stage 1: Syntax & Schema Validation
    ├── Conformance to Sigma generic specification v2.0
    ├── Valid UUIDv4 identifier
    ├── Mandatory MITRE ATT&CK technique tags (attack.tXXXX)
    └── Severity level and rationale presence

 Stage 2: Positive Telemetry Verification (True Positive Assertions)
    ├── Rule logic executed against attack dataset
    ├── Must trigger intended alert count with matching entity artifacts
    └── Event context verification (User, Host, Process, Command line)

 Stage 3: Negative Telemetry Verification (False Positive Tuning)
    ├── Rule logic executed against benign enterprise baseline
    ├── Identify unintended triggers caused by legitimate admin behavior
    └── Author tuning exceptions and log trade-off analysis in tuning register
```

### 4.1 Reproducibility Standard
In accordance with PRD Section 5:
- Any detection engineer or auditor must be able to run the automated testing harness (`python tools/harness.py`) and observe identical match counts against the published dataset without external network calls or proprietary dependencies.
- Every claim of detection coverage must reference an active, tested Sigma rule and verifiable log fields.

---

## 5. Threat Hunting Methodology: The Hypothesis Loop

Threat hunting operates proactively to discover unalerted threat behaviors lurking within log archives. Cyberion executes threat hunts following the 4-phase Hypothesis-Driven Hunting Model:

```
[ Phase 1: Threat Intelligence & TTP Profiling ]
                        │
                        ▼
[ Phase 2: Hypothesis Formulation (Falsifiable & Specific) ]
                        │
                        ▼
[ Phase 3: Telemetry Querying & Behavioral Analytics (Delta-T, Clustering) ]
                        │
                        ▼
[ Phase 4: Finding Verification & Triage ]
       ├── If Confirmed: Escalate to Incident Response Case
       └── If Negative/Inconclusive: Document Hunting Baselines & Close
```

1. **Hypothesis Formulation:** A falsifiable statement positing adversary presence via a specific technique not covered by existing alert logic.
2. **Analysis Execution:** Applying statistical aggregations (e.g. inter-arrival beaconing variance, rare parent-child process pairs, entropy analysis of domain queries).
3. **Outcome Documentation:** Complete reporting of positive finds or transparent documentation of negative results (ruling out techniques proves defensibility).
4. **Content Feedback:** If an adversary technique is discovered, it immediately feeds into the Detection Engineering Workflow to generate a permanent Sigma detection rule.

---
*Approved by:*  
**Manager, Detection Engineering — Cyberion Defense Labs**
