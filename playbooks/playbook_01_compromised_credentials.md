# Incident Response Playbook: Compromised Credential Use
**Playbook Reference:** CDL-IRP-01  
**Category:** Identity Threat Detection & Response (ITDR)  
**ATT&CK Techniques:** T1078 (Valid Accounts), T1110 (Brute Force), T1098 (Account Manipulation)  
**Target Roles:** SOC Analysts (Tier 1/Tier 2), Incident Response Lead, Active Directory Admin  
**Version:** 2.0  
**Last Updated:** 2026-10-08

---

## 1. Trigger Conditions & Alert Indicators

This playbook is activated upon any of the following triggers:
- **SIEM Alert:** Correlation rule `CDL-RULE-016` (Brute Force followed by successful logon within 5 minutes).
- **Identity Alert:** Microsoft Entra ID / Okta "Impossible Travel" alert (logons from geographically distant locations within an impossible timeframe).
- **MFA Fatigue Alert:** Multiple denied MFA push notifications followed by an approved push outside user's business hours.
- **Privilege Elevation:** Windows Security Event 4728 / 4732 (`CDL-RULE-007`) adding an account to Domain Admins without an approved change ticket.
- **Service Account Interactive Logon:** Windows Security Event 4624 (LogonType 2 or 10) for any service account (`svc_*`).

---

## 2. Phase 1: Triage & Initial Scoping

```
[ Step 1.1: Verify Alert Legitimacy ]
   ├── Query SIEM for authentication history for target user over past 14 days.
   ├── Determine if source IP is known corporate VPN, internal subnet, or public proxy/VPN/Tor node.
   └── Check Change Management / ServiceDesk queue for scheduled maintenance or user travel.

[ Step 1.2: Scope User Account Privileges ]
   ├── Enumerate Active Directory group memberships (Domain Admins, Enterprise Admins, Local Admins).
   ├── Check if account has access to sensitive databases, code repositories, or customer PII.
   └── Determine account type: Standard User, Privileged Human, Service Account, or Cloud Only.

[ Step 1.3: Audit Contemporaneous User Actions ]
   ├── Query Sysmon Event 1 (Process Creation) and Windows Event 4688 on the target workstation for 60 minutes post-logon.
   └── Check for reconnaissance commands: whoami, net group, nltest, adfind, or PowerShell scripts.
```

---

## 3. Phase 2: Containment Procedures (Target Time: < 15 Minutes)

Execute containment steps immediately upon verifying unauthorized access:

1. **Disable / Lock Active Directory & Cloud Account:**
   ```powershell
   # On Active Directory Domain Controller:
   Disable-ADAccount -Identity "target_username"
   # Revoke all Azure AD / Microsoft 365 Refresh Tokens:
   Revoke-AzureADUserAllRefreshToken -ObjectId "user-guid"
   ```
2. **Invalidate Active Kerberos Ticket Granting Tickets (TGT):**
   - Terminate existing sessions across member servers:
   ```cmd
   klist -li 0x3e7 purge
   ```
3. **Endpoint Isolation:**
   - If the user authenticated from an internal corporate workstation, immediately issue network isolation via EDR console (allow only SIEM/EDR management tunnel).
4. **Perimeter Session Teardown:**
   - Terminate active VPN and firewall sessions associated with the user:
   ```bash
   vpn-admin disconnect user target_username
   ```

---

## 4. Phase 3: Eradication & Remediation

1. **Password & Credential Reset:**
   - Reset user password with a minimum 20-character randomly generated string.
   - Enforce "User must change password at next logon".
   - Revoke and re-enroll MFA hardware tokens / Microsoft Authenticator registrations.
2. **Inspect Persistence & Backdoors:**
   - Query Active Directory for modified account attributes (Event 4738): check for added SPNs, modified `userWorkstations`, or altered delegation rights (`TrustedForDelegation`).
   - Audit mailbox forwarding rules in Exchange/O365:
     ```powershell
     Get-InboxRule -Mailbox "target_user" | Select Name, ForwardTo, RedirectTo
     ```
   - Check local scheduled tasks (`CDL-RULE-009`) and Registry Run keys (`CDL-RULE-010`) on any host logged into by the account.
3. **Double `krbtgt` Reset (If Domain Admin Compromised):**
   - If a Domain Admin account was compromised, execute the Microsoft `New-KrbtgtKeys.ps1` script to perform a 2-stage reset of the Active Directory `krbtgt` account, invalidating forged Golden Tickets.

---

## 5. Phase 4: Recovery & Post-Incident Verification

1. Re-enable account only after full password reset, MFA re-registration, and user identity verification via out-of-band video or manager attestation.
2. Maintain enhanced monitoring on the account for 30 days (enable debug auditing on all authentication requests).
3. Conduct root-cause retrospective: identify how credentials leaked (phishing site, infostealer malware, password reuse, cleartext script).

---

## 6. Stakeholder Communications & Reporting Matrix

| Stakeholder | Timing | Communication Method | Information Required |
|:---|:---|:---|:---|
| **Incident Commander** | Within 5 minutes of triage confirmation | Encrypted War Room (Signal / Teams) | Affected username, privilege level, suspected attack vector, containment status. |
| **Active Directory Team** | Immediate (<10 min) | Secure Direct Call / Ticket | Target account name, SID, isolation request, krbtgt reset coordination. |
| **Affected User's Manager**| Within 30 minutes | Phone Call & Secure Email | Notice of account suspension, verification of employee location/activity. |
| **CISO / Legal Counsel** | Within 1 hour (if Domain Admin/PII involved) | Executive Incident Briefing | Breach scope assessment, regulatory notification requirements (GDPR/HIPAA/SEC). |
| **MSSP Client Contact** | Within SLA (15 min for Critical) | MSSP Client Incident Portal | Incident ticket, indicators, containment actions taken, client action items. |

---
*Authorized by:*  
**Cyberion Incident Response Practice**
