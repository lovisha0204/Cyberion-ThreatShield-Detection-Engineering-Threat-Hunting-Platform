# Cyberion Defense Labs — Detection Engineering & Threat Hunting Briefing
**Engagement Code:** CDL-DET-V2  
**Format:** Executive Presentation Deck (Slide-by-Slide Briefing)  
**Presented To:** Director of Security Operations & CISO Advisory Board  
**Presenter:** Detection Engineering Practice  
**Date:** 2026-10-08

---

### Slide 1: Title & Engagement Scope
# Detection Engineering & Threat Hunting Practice Modernization
### Transforming Reactive SOC Operations into an Evidence-Based Defense Engine
- **Presenter:** Detection Engineering & Threat Intelligence Practice
- **Engagement Duration:** 4-Week Sprint (CDL-DET-V2)
- **Scope:** 18 Sigma Rules | 26 MITRE ATT&CK Techniques | 2 Threat Hunts | 2 Incidents Investigated | 3 Playbooks

*Speaker Notes:* Welcome leadership and colleagues. Today we present the culmination of our 4-week detection engineering sprint. Over the past month, we transitioned Cyberion from unmeasured, informal detection logic into a defensible, framework-aligned, and tested detection engineering capability.

---

### Slide 2: The Business Challenge: Where We Started
## The Pre-Sprint Reality
- **Invisible Blind Spots:** No formal mapping to MITRE ATT&CK; unable to answer client audits on whether specific adversary TTPs were detected.
- **Untested Logic:** Detections written as one-off queries in unstructured wikis with zero test telemetry or version control.
- **Alert Fatigue:** High false-positive rates caused tier-1 analysts to miss genuine malicious signals.
- **Inconsistent Response:** Incident investigations were ad-hoc without structured response playbooks or root cause feedback loops.

*Speaker Notes:* Our problem was not a lack of data—our SIEM was ingesting terabytes of logs daily. Our problem was the absence of an engineered detection lifecycle. Rules were written reactively and never tested against authentic attacker behavior.

---

### Slide 3: Telemetry Foundation & Data Harmonization
## Grounding Detections in Verifiable Telemetry
- **Multi-Sensor Visibility:**
  - **Windows Security Audit:** User authentication (4624/4625), privilege escalation (4672), security groups (4728), Kerberos (4769).
  - **Microsoft Sysmon:** Process trees (EID 1), memory access to LSASS (EID 10), network sockets (EID 3), registry persistence (EID 13).
  - **Zeek Network Security Monitor:** Wire-level protocol telemetry (`conn.log`, `dns.log`, `http.log`, `ssl.log`).
- **Data Repositories Utilized:**
  - Mordor Project (OTRF) adversary emulations (Empire, Cobalt Strike, APT29).
  - Public EVTX-ATTACK-SAMPLES repository.
  - Splunk Boss of the SOC (BOTS) datasets.
  - Atomic Red Team test suites executed in instrumented lab environments.

*Speaker Notes:* Every detection rule in our repository was engineered and tested against real attack telemetry. We refuse to deploy detection content on theoretical assumptions.

---

### Slide 4: Detection Rule Library & Format Portability
## Version-Controlled Sigma Rule Library (18 Rules Delivered)
- **Open Standard Architecture:** All rules authored in Sigma specification v2.0 for SIEM independence.
- **Cross-Platform Portability:**
  - Automated translation to **Splunk SPL** (`splunk_queries.spl`).
  - Automated translation to **Microsoft Sentinel KQL** (`sentinel_queries.kql`).
- **Rule Categorization:**
  - 15 Technique-Specific Standard Rules targeting Execution, Credential Access, Defense Evasion, Persistence, and C2.
  - 3 Advanced Correlation Rules (Temporal Brute-Force to Success, Recon to Lateral Hop, LSASS Memory Dump to C2 Egress).

*Speaker Notes:* By writing in Sigma, our detection content is portable across any SIEM backend, whether a client runs Splunk, Microsoft Sentinel, or Elastic. Furthermore, our 3 correlation rules move beyond single-event alerts to catch multi-stage adversary sequences.

---

### Slide 5: MITRE ATT&CK Coverage Assessment
## Defensible Coverage Across the Adversary Lifecycle
- **26 Techniques Evaluated across 9 Enterprise Tactics**
- **76.9% Fully Covered (20 Techniques)** with validated Sigma rules.
- **19.2% Partially Covered (5 Techniques)** with targeted threat hunt analytics.
- **3.9% Explicit Gaps (1 Technique - T1562.001 Tool Tampering)** placed on immediate sprint backlog.
- **Deliverable:** Official MITRE ATT&CK Navigator Layer (`cyberion_attck_navigator_layer.json`) ready for client audit briefings.

*Speaker Notes:* We can now show our clients an exact, color-coded MITRE ATT&CK Navigator matrix. When a customer asks if we detect Kerberoasting or PsExec lateral movement, we have the rule ID, test telemetry, and coverage score ready immediately.

---

### Slide 6: Proactive Threat Hunting Program
## From Reactive Waiting to Hypothesis-Driven Hunting
- **Hunt 01: Covert HTTP/S C2 Beaconing with Sleep Jitter (T1071.001)**
  - Applied inter-arrival variance ($\Delta t$) and standard deviation modeling ($\sigma / \mu < 0.35$).
  - **Finding:** Isolated workstation `WKSTN-FIN-01` communicating with Cobalt Strike C2 IP `185.106.94.234:8443` with 45s interval and 11.9% jitter.
- **Hunt 02: Silent LOLBAS & Host Reconnaissance (T1082 / T1016)**
  - Audited tumbling 3-minute burst clusters of native Windows discovery tools (`whoami`, `systeminfo`, `nltest`).
  - **Finding:** Uncovered compromised backup service account (`svc_backup`) conducting unapproved AD discovery on `WS-FIN-04`.

*Speaker Notes:* Proactive threat hunting works. Both hunts generated verified true-positive adversary discoveries that bypassed standard antivirus, feeding directly into full incident investigations.

---

### Slide 7: Incident Investigations & Case Outcomes
## Rapid Containment of Critical Intrusions
- **Case INC-2026-0841: Cobalt Strike Ingress & DC Pivot (P1 - Critical)**
  - Phishing attachment $\rightarrow$ PowerShell cradle $\rightarrow$ LSASS dump $\rightarrow$ PsExec to `DC-01`.
  - **Outcome:** Contained in 25 minutes. Network isolation, perimeter drop, double `krbtgt` password reset prevented domain destruction and ransomware rollout.
- **Case INC-2026-0894: Backup Principal Compromise & NTDS.dit Staging (P2 - High)**
  - Leaked script credentials $\rightarrow$ WinRM lateral hop $\rightarrow$ Volume Shadow Copy cloning of `ntds.dit` $\rightarrow$ DNS tunneling probe.
  - **Outcome:** Contained prior to exfiltration completion. Staged 7-Zip archives purged; backup infrastructure migrated to gMSA.

*Speaker Notes:* Both incidents were documented with complete raw log timelines, 5-Whys root cause analyses, and closed as True Positives with executive sign-off.

---

### Slide 8: Rule Quality & False Positive Tuning
## Eliminating Alert Fatigue: 99.6% Noise Reduction
- **CDL-RULE-001 (PowerShell Cradles):** Whitelisted legitimate RMM agents (NinjaRMM/Kaseya) $\rightarrow$ Alert noise reduced from 184/day to 0/day.
- **CDL-RULE-002 (LSASS Process Access):** Filtered Microsoft Defender for Endpoint (`MsSense.exe`) and OS health calls $\rightarrow$ Alert noise reduced from 512/day to 0/day.
- **CDL-RULE-009 (Scheduled Tasks):** Required privileged context or script interpreters $\rightarrow$ Alert noise reduced from 78/day to 0/day.
- **Aggregate Result:** 774 daily false-positive alerts eliminated, restoring tier-1 analyst bandwidth.

*Speaker Notes:* Detection engineering is not just about writing rules—it is about writing high-precision rules that analysts actually trust. A rule that fires 500 false alerts a day is as dangerous as having no rule at all.

---

### Slide 9: Standardized Incident Response Playbooks
## Repeatable, Time-Tested Response Procedures
- **Playbook 01: Compromised Credential Use (T1078, T1110)**
  - Impossible travel, MFA fatigue, token revocation, active TGT purging, and account suspension workflows.
- **Playbook 02: Lateral Movement via Remote Services (T1021.002, T1047, T1569.002)**
  - Dual-endpoint isolation, service termination, internal subnet segmentation, and memory acquisition.
- **Playbook 03: Command & Control Beaconing (T1071.001, T1071.004)**
  - Jitter analysis, perimeter null-routing, DNS sinkholing, process termination, and memory config extraction.

*Speaker Notes:* Response quality no longer depends on which analyst is on duty. Every response action follows a standardized, timed procedure with clear stakeholder communications.

---

### Slide 10: Conclusion & 90-Day Roadmap
## Building Long-Term Defensibility
- **Immediate (30 Days):** Enforce AD administrative tiering and enable Windows Defender Credential Guard enterprise-wide.
- **Mid-Term (60 Days):** Push converted Splunk SPL and Sentinel KQL rules to production client SIEMs; automate threat intel watchlist lookups.
- **Strategic (90 Days):** Deploy automated rule testing harness into Git CI/CD pipeline; conduct quarterly Purple-Team adversary emulation exercises.

**Thank you. Questions & Discussion.**

---
*Cyberion Defense Labs — Detection Engineering Practice*
