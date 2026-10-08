# Threat Hunt Report: Covert HTTP/S C2 Beaconing with Sleep Jitter
**Hunt Reference:** CDL-HUNT-01  
**Technique Mapped:** T1071.001 (Application Layer Protocol: Web Protocols)  
**Lead Threat Hunter:** Cyberion Detection Engineering Practice  
**Date Executed:** 2026-10-08  
**Status / Outcome:** **CONFIRMED FINDING (Escalated to Incident Response)**  
**Escalation Target:** Case [`INC-2026-0841`](file:///c:/Users/Hp/Desktop/cyber/incident_reports/incident_case_001_cobalt_strike_intrusion.md)

---

## 1. Threat Intelligence & Rationale

Adversaries deploying Command and Control (C2) implants (e.g. Cobalt Strike, Sliver, Brute Ratel) routinely introduce randomization ("sleep jitter") between outbound communication pulses to defeat static threshold alarms (e.g. alerts triggering on connections occurring precisely every 60 seconds). In a modern enterprise, thousands of benign applications generate periodic HTTP/S polling (telemetry agents, software updaters). 

This hunt was designed to isolate non-browser outbound traffic exhibiting low delta-T variance (inter-arrival regularity despite jitter), uniform packet byte distributions, and rare destination server profiles.

---

## 2. Hunt Hypothesis

> **Hypothesis:** One or more endpoints within the corporate workstation subnet are infected with an undetected C2 stager communicating outbound over HTTP/S with an external IP address on an irregular but statistically bounded polling interval (mean sleep interval 30–60s with 10–25% jitter), evading signature-based web gateway filters.

---

## 3. Data Sources & Query Methodology

### 3.1 Telemetry Scope
- **Network Telemetry:** Zeek `http.log` and `conn.log` from perimeter sensors (monitoring internal subnet `192.168.10.0/24`).
- **Endpoint Telemetry:** Microsoft Sysmon Event ID 3 (Network Connection) and Event ID 1 (Process Creation).
- **Timeframe:** 24-hour analysis window.

### 3.2 Analytical Approach & Splunk / Python Syntax

The hunter calculated the inter-arrival time ($\Delta t$) between consecutive outbound connections grouped by `(id.orig_h, id.resp_h, id.resp_p)`.

```spl
index=zeek sourcetype="zeek:conn" id_resp_h!=10.0.0.0/8 id_resp_h!=172.16.0.0/12 id_resp_h!=192.168.0.0/16
| sort 0 id_orig_h, id_resp_h, _time
| streamstats current=f window=1 last(_time) as prev_time by id_orig_h, id_resp_h
| eval delta_t = _time - prev_time
| stats count, avg(delta_t) as mean_interval, stdev(delta_t) as std_interval, 
        avg(orig_bytes) as avg_sent, avg(resp_bytes) as avg_rcvd,
        min(_time) as first_seen, max(_time) as last_seen 
  by id_orig_h, id_resp_h, id_resp_p
| eval jitter_ratio = round(std_interval / mean_interval, 3)
| where count > 50 AND mean_interval >= 20 AND mean_interval <= 120 AND jitter_ratio < 0.35
| sort jitter_ratio asc
```

### 3.3 Evaluation Metrics
- **Count:** Minimum 50 persistent connections over the observation window.
- **Mean Interval ($\mu$):** Between 20s and 120s.
- **Jitter Ratio ($\sigma / \mu$):** Standard deviation divided by the mean. A ratio $< 0.35$ strongly signifies automated algorithmic polling rather than human browsing behavior.

---

## 4. Empirical Findings & Observations

### 4.1 Statistical Outlier Isolation

The query surfaced a stark statistical anomaly connecting endpoint `192.168.10.115` (`WKSTN-FIN-01`) to external IP `185.106.94.234` on port `8443`:

| Source IP | Destination IP | Dest Port | Total Conn | Mean $\Delta t$ (s) | Std Dev $\sigma$ (s) | Jitter Ratio | Avg Sent | Avg Rcvd |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `192.168.10.115` | **`185.106.94.234`** | **`8443`** | **1,412** | **45.2 s** | **5.4 s** | **0.119** | **388 B** | **1,240 B** |
| `192.168.10.115` | `142.250.190.46` | `443` (Google) | 482 | 142.8 s | 129.4 s | 0.906 | 1.8 KB | 14.2 KB |
| `192.168.10.22` | `20.190.159.2` | `443` (MSFT) | 890 | 85.1 s | 62.3 s | 0.732 | 920 B | 8.9 KB |

*Observation:* While legitimate cloud traffic displayed erratic jitter ratios ($>0.70$), the traffic to `185.106.94.234` clustered tightly around 45 seconds with a standard deviation of only 5.4 seconds (a calculated jitter of 11.9%).

### 4.2 Endpoint Correlation (Sysmon)

Cross-referencing `192.168.10.115` on destination port `8443` in Sysmon Event ID 3 revealed:
- **Initiating Process:** `C:\Windows\System32\rundll32.exe` (PID: 4892)
- **User Context:** `CYBERION\jdoe`
- **Parent Image:** `C:\Windows\explorer.exe` (spawning a malicious helper DLL from `C:\Users\jdoe\AppData\Local\Temp\sqlncli.dll`)

### 4.3 Negative Results Documented
- Audited 14 other external endpoints flagged with regular intervals. 13 were validated as benign SaaS push telemetry (e.g., Slack WebSocket heartbeats, Microsoft Teams presence polls).
- Ruled out beaconing behavior across the server VLAN (`192.168.20.0/24`).

---

## 5. Conclusion & Actionable Next Steps

- **Conclusion:** **CONFIRMED ATTACKER C2 PRESENCE.** The hypothesis was unequivocally confirmed. An active Cobalt Strike HTTP/S beacon is executing on `WKSTN-FIN-01`.
- **Incident Escalation:** Handoff immediately to Incident Response under Case ID **`INC-2026-0841`**.
- **Detection Engineering Feedback:**
  - Standardized the jitter calculation logic into an automated analytics model.
  - Authored Sigma rule `CDL-RULE-005` to catch the underlying HTTP URI characteristics.
  - Deployed perimeter firewall block on `185.106.94.234:8443`.

---
*Signed by:*  
**Lead Threat Hunter, Cyberion Defense Labs**
