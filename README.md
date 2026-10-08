# Cyberion Defense Labs — Detection Engineering & Threat Hunting Engagement
**Project Code:** CDL-DET-V2  
**Engagement Model:** Security Engineering Individual Contributor Track (Advanced / Intermediate Level)  
**Classification:** Internal Security Operations Deliverables  
**Target Platform:** Windows Security, Sysmon v15, Zeek Network Sensor, Splunk ES, Microsoft Sentinel  

---

## 1. Project Overview

This repository contains the complete technical deliverables for the **Cyberion Defense Labs Detection Engineering & Threat Hunting Engagement (CDL-DET-V2)**. Cyberion Defense Labs operates as a Managed Security Service Provider (MSSP). This project modernizes the SOC detection lifecycle by moving away from ad-hoc tribal knowledge into an audit-defensible, version-controlled library of **Sigma detection rules**, structured **threat hunts**, **incident case investigations**, and **incident response playbooks** mapped directly to the **MITRE ATT&CK Enterprise Framework**.

---

## 2. Repository Architecture & Deliverables Index

```
c:\Users\Hp\Desktop\cyber\
├── .git/                                    # Version-controlled Git repository with structured milestones
├── README.md                                # Master project documentation & verification guide
├── requirements.txt                         # Python dependencies (pyyaml)
│
├── data_dictionary/
│   └── telemetry_data_dictionary.md         # Windows Security, Sysmon, and Zeek field catalog & detection value
│
├── methodology/
│   └── telemetry_methodology.md             # Dataset acquisition (Mordor, BOTS, EVTX) and replay protocol
│
├── rules/                                   # 18 Production-Grade Sigma Rules (15 Standard + 3 Correlation)
│   ├── rules_index.md                       # Master index catalog of all rules with metadata & rationale
│   ├── CDL-RULE-001_powershell_download_cradle.yml           (T1059.001 - PowerShell Cradles)
│   ├── CDL-RULE-002_mimikatz_lsass_dump.yml                  (T1003.001 - LSASS Memory Dump)
│   ├── CDL-RULE-003_psexec_service_installation.yml          (T1569.002 - PsExec Remote Exec)
│   ├── CDL-RULE-004_wmi_process_creation.yml                 (T1047 - WMI Remote Spawn)
│   ├── CDL-RULE-005_c2_periodic_beaconing_http.yml           (T1071.001 - C2 HTTP Beaconing)
│   ├── CDL-RULE-006_ntds_dit_volume_shadow_copy.yml          (T1003.003 - NTDS.dit Shadow Copy)
│   ├── CDL-RULE-007_user_added_to_domain_admins.yml          (T1098 - Domain Admins Addition)
│   ├── CDL-RULE-008_suspicious_rundll32_execution.yml        (T1218.011 - Rundll32 Proxy Exec)
│   ├── CDL-RULE-009_scheduled_task_creation_schtasks.yml     (T1053.005 - Scheduled Tasks)
│   ├── CDL-RULE-010_reg_run_key_persistence.yml              (T1547.001 - Registry Run Keys)
│   ├── CDL-RULE-011_dns_txt_record_exfiltration.yml          (T1071.004 - DNS TXT Tunneling)
│   ├── CDL-RULE-012_suspicious_certutil_download.yml         (T1105 - Certutil LOLBAS Transfer)
│   ├── CDL-RULE-013_mshta_obfuscated_vbs.yml                 (T1218.005 - Mshta Inline Script)
│   ├── CDL-RULE-014_remote_desktop_tunneling.yml             (T1021.001 - Netsh RDP Tunneling)
│   ├── CDL-RULE-015_kerberoasting_spn_request.yml            (T1558.003 - Kerberoasting RC4 TGS)
│   ├── CDL-RULE-016_correlation_brute_force_to_success.yml   (T1110 -> T1078 Correlation)
│   ├── CDL-RULE-017_correlation_recon_to_lateral_movement.yml(T1087 -> T1021 Correlation)
│   └── CDL-RULE-018_correlation_lsass_dump_to_c2_egress.yml (T1003.001 -> T1071 Correlation)
│
├── conversions/                             # SIEM Backend Portability (Multi-SIEM Translation)
│   ├── splunk_queries.spl                   # Sample Splunk SPL search queries
│   ├── sentinel_queries.kql                 # Sample Microsoft Sentinel KQL search queries
│   ├── all_rules_splunk.spl                 # Complete Splunk SPL queries for all 18 rules
│   ├── all_rules_sentinel.kql               # Complete Microsoft Sentinel KQL queries for all 18 rules
│   └── all_rules_elastic.esql               # Complete Elasticsearch / OpenSearch ESQL queries for all 18 rules
│
├── coverage/                                # MITRE ATT&CK Framework Mapping
│   ├── mitre_coverage_matrix.md             # 26 Techniques assessed across 9 tactics with gap analysis
│   └── cyberion_attck_navigator_layer.json  # Official MITRE ATT&CK Navigator v4.5 JSON layer
│
├── threat_hunts/                            # Hypothesis-Driven Threat Hunting Reports
│   ├── hunt_01_c2_covert_beaconing.md       # Hunt 1: Low-frequency C2 Jitter & Delta-T Analysis (Confirmed -> INC-001)
│   └── hunt_02_lolbins_wmi_reconnaissance.md # Hunt 2: LOLBAS & Burst Discovery on Service Accounts (Confirmed -> INC-002)
│
├── incident_reports/                        # End-to-End Incident Investigation Case Reports
│   ├── incident_case_001_cobalt_strike_intrusion.md  # Case INC-2026-0841 (Phishing -> Mimikatz -> DC PsExec)
│   └── incident_case_002_finance_insider_staging.md  # Case INC-2026-0894 (Backup Account -> VSS NTDS.dit -> DNS Staging)
│
├── playbooks/                               # Standardized Incident Response Playbooks
│   ├── playbook_01_compromised_credentials.md        (CDL-IRP-01: T1078 / T1110 / Identity Response)
│   ├── playbook_02_lateral_movement_remote_services.md(CDL-IRP-02: T1021.002 / T1047 / Lateral Hop Isolation)
│   └── playbook_03_c2_beaconing_investigation.md     (CDL-IRP-03: T1071.001 / T1071.004 / Perimeter Null-Route)
│
├── ioc_research/                            # Threat Intelligence Research & Operationalization
│   ├── ioc_threat_intelligence_notes.md     # Campaign attribution (Cobalt Strike, APT29, FIN7) & pipeline design
│   └── watchlists/                          # Ingestion-ready CSV watchlists
│       ├── malicious_ips.csv
│       ├── malicious_domains.csv
│       └── malicious_hashes.csv
│
├── tuning/
│   └── false_positive_tuning_passes.md      # Documented tuning passes for 3 rules (99.6% noise reduction)
│
├── executive_summary/
│   └── executive_summary_report.md          # Business-level summary for CISO & executive stakeholders
│
├── presentation/
│   ├── cyberion_executive_presentation.md   # Slide-by-slide markdown executive deck
│   └── cyberion_presentation.html           # Interactive HTML responsive presentation with dark mode & controls
│
├── purple_team/                             # Purple Teaming Exercise Plans
│   └── purple_team_exercise_plan.md         # Master matrix pairing all 18 rules with Red/Blue/White procedures
│
├── emulation/                               # Adversary Emulation & Simulation
│   ├── atomic_red_team_guide.md             # Complete Atomic Red Team test execution guide
│   └── simulate_telemetry.py                # Python adversary telemetry generator
│
├── dashboard/                               # Security Operations Portal
│   └── index.html                           # Standalone interactive dashboard with live matrix & timelines
│
├── data/                                    # Verifiable Telemetry Corpora
│   ├── attack_telemetry.json                # Positive attack event sequences matching all 18 rules
│   └── benign_telemetry.json                # Enterprise normal baseline logs for false-positive validation
│
├── tools/                                   # Automation & Verification Tooling
│   ├── harness.py                           # Python Sigma rule test harness & evaluation engine
│   └── sigma_converter.py                   # Automated CLI translator from Sigma YAML to SPL / KQL
│
├── tests/
│   └── test_rule_integrity.py              # Automated unit test suite verifying schema, tags, and hits
│
├── verify_all.py                            # Master audit runner validating all 32 deliverables & tests
└── audit_report.json                        # Timestamped JSON audit compliance certificate
```

---

## 3. PRD Success Criteria & Verification Matrix

| PRD Section | Target Metric | Required Target | Delivered Result | Status |
|:---|:---|:---:|:---:|:---:|
| **2.7 & 4.2** | Detection Rules Delivered | 15+ Sigma rules | **18 Rules** (15 standard + 3 correlation) | **Exceeded** |
| **4.2** | Correlation Rules | $\ge 3$ Rules | **3 Rules** (`CDL-RULE-016`, `017`, `018`) | **Met** |
| **2.7 & 4.3** | ATT&CK Techniques Assessed | $\ge 20$ Techniques | **26 Techniques** across 9 tactics | **Exceeded** |
| **4.3** | ATT&CK Navigator Export | Layer file | **`cyberion_attck_navigator_layer.json`** | **Met** |
| **4.4** | Structured Threat Hunts | $\ge 2$ Hunts | **2 Hunts** (both confirmed findings) | **Met** |
| **4.4** | Hunt on Uncovered Technique | $\ge 1$ Hunt | **CDL-HUNT-02** (T1082 / T1016 LOLBAS Recon) | **Met** |
| **4.6** | Full Incident Case Reports | $\ge 2$ Reports | **2 Cases** (`INC-2026-0841`, `INC-2026-0894`) | **Met** |
| **4.7** | Incident Response Playbooks | $\ge 3$ Playbooks | **3 Playbooks** (Credentials, Lateral, C2) | **Met** |
| **4.8** | False Positive Tuning Passes | $\ge 3$ Rules | **3 Rules Tuned** (99.6% noise reduction) | **Met** |
| **4.5** | IOC Intelligence Notes & Feeds | Documented notes | **Notes + 3 CSV Watchlists** | **Met** |
| **4.9** | Executive Summary Report | Business report | **`executive_summary_report.md`** | **Met** |
| **11 & 15** | Python Rule Testing Harness | Local runner | **`tools/harness.py`** | **Met** |
| **11 & 15** | Rule Validation Coverage | 100% Tested | **18 / 18 Rules (100% Pass Rate)** | **Met** |
| **11** | SIEM Query Conversions | SPL / KQL | **`splunk_queries.spl` & `sentinel_queries.kql`** | **Met** |
| **12** | Presentation Deck | Slide format | **Markdown Deck + Interactive HTML Deck** | **Met** |

---

## 4. How to Run & Verify the Project

### 4.1 Prerequisites
- Python 3.11+ (Python 3.14.6 tested)
- `pyyaml` (Installed via `pip install pyyaml` or `pip install -r requirements.txt`)

### 4.2 Run the Automated Rule Testing Harness
Execute the rule evaluation harness to validate all 18 Sigma rules against positive attack telemetry and the benign baseline:
```bash
python tools/harness.py
```
**Expected Output:**
- `SCHEMA & SYNTAX CHECK: 100% PASS`
- `18 / 18 rules matched against attack telemetry (True Positives)`
- `0 false positives on benign baseline (100% False Positive Resilience)`

### 4.3 Run the Comprehensive Unit Test Suite
Execute the unit test suite to verify rule schema integrity, UUID formats, MITRE ATT&CK tags, and Navigator JSON schema:
```bash
python tests/test_rule_integrity.py
```
**Expected Output:**
- `Ran 8 tests in 0.055s — OK`

### 4.4 Convert Sigma Rules to Splunk SPL or Sentinel KQL
Run the automated CLI converter tool:
```bash
# Convert a specific rule to both Splunk and Sentinel:
python tools/sigma_converter.py --rule rules/CDL-RULE-001_powershell_download_cradle.yml --format both

# Convert specifically to Splunk SPL:
python tools/sigma_converter.py --rule rules/CDL-RULE-002_mimikatz_lsass_dump.yml --format splunk
```

### 4.5 View the Executive Presentation
Open `presentation/cyberion_presentation.html` in any web browser (Chrome, Edge, Firefox, Safari) to interactively present the findings to stakeholders. Navigate using on-screen buttons or arrow keys.

### 4.6 Inspect the ATT&CK Navigator Layer
Open the official [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) and upload `coverage/cyberion_attck_navigator_layer.json` to view the interactive matrix with color-coded coverage layers.

---

## 5. Version Control & Git Commit History

In accordance with PRD Section 5 & Section 13, all deliverables are tracked with structured commit milestones representing the 4-week delivery roadmap:
- `Week 1: Data Familiarization & Repository Setup`
- `Week 2: Detection Rule Engineering & ATT&CK Coverage Matrix`
- `Week 3: Threat Hunting, Incident Cases & Response Playbooks`
- `Week 4: Finalization, Tuning, Conversions & Executive Presentation`

---
*Maintained by:*  
**Detection Engineering & Threat Intelligence Practice**  
**Cyberion Defense Labs**
