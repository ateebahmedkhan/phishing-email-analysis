# Incident Report 003 — Zendesk Platform Abuse / Crypto Wallet Phishing
**Date Analyzed:** June 2026
**Sample Source:** phishing_pot (public phishing repository)
**Severity:** Critical
**Status:** Analyzed

**Tool Output:** See [sample3_output.png](sample3_output.png) and [sample3_output.txt](sample3_output.txt)

---

## Executive Summary
A highly sophisticated phishing email that passes all three email authentication checks — SPF, DKIM, and DMARC — by abusing Zendesk's legitimate customer support platform to send the attack. The email targets crypto wallet holders using urgency manipulation. Because it originates from Zendesk's own infrastructure, it bypasses most email security filters entirely. Detection requires behavioral analysis rather than authentication checks alone.

---

## Indicators of Compromise (IOCs)

| Type | Value | Verdict |
|------|-------|---------|
| From Domain | pcpilrjf.zendesk.com | Attacker-created free Zendesk account |
| Sending IP | 188.172.137.15 | Zendesk's legitimate server — UK |
| Redirect URL | trans.mailnr.com | Obfuscated tracking redirect |
| Hosted Image | s3.ap-south-1.amazonaws.com | AWS Mumbai — unrelated to Zendesk |
| Subject | Verify Your Wallet Now | Urgency tactic — crypto credential harvesting |

---

## Detailed Analysis

### 1. Living Off Trusted Infrastructure
This is the most significant finding across all three samples analyzed. The attacker registered a free Zendesk account (`pcpilrjf.zendesk.com`) and used Zendesk's own mail servers to send the phishing email. Because Zendesk is a globally trusted platform, SPF, DKIM, and DMARC all pass — the email is technically authentic. This technique is called "living off trusted infrastructure" and is specifically designed to bypass automated email security filters.

### 2. All Authentication Passes — Still Phishing
- **SPF:** Pass — Zendesk's IP is authorized to send for zendesk.com subdomains
- **DKIM:** Pass — signature verified against Zendesk's legitimate public key
- **DMARC:** Pass — policy satisfied

This is the critical lesson from this sample: passing authentication does not mean the email is safe. Authentication only verifies the sending platform, not the intent of the sender. A SOC analyst must always apply behavioral analysis on top of authentication results.

### 3. Urgency and Social Engineering
The subject line "Verify Your Wallet Now to Ensure Safe and Smooth Access" targets crypto wallet holders and creates urgency. The word "Now" and the implied threat of losing access are deliberate social engineering tactics designed to bypass the victim's critical thinking.

### 4. Obfuscated Redirect URL
The payload URL is:http://trans.mailnr.com/DRAYLF?id=111651=dkxVUAIIDgAHHlMMAgxTBQQHAFtQVF9SBAkAUgoBBlEFAVdQUVhbBARVAlY

The long encoded parameter string is designed to obscure the final destination. This is a tracking redirect that logs the victim's click before forwarding them to the credential harvesting page.

### 5. AWS S3 Mumbai Hosted Image
Images in the email are hosted on AWS S3 in the Mumbai region (`ap-south-1`). A legitimate customer support email from a Western platform would not host assets in Mumbai. This is a geographic anomaly indicator suggesting the attacker is operating from or targeting South Asia.

### 6. Suspicious Zendesk Subdomain
The subdomain `pcpilrjf` is a randomly generated string — characteristic of attacker-created free accounts. Legitimate businesses use recognizable subdomains like `companyname.zendesk.com`. A random 8-character string is a strong indicator of a throwaway account.

---

## Threat Intelligence Enrichment

### AbuseIPDB — Sending IP: 188.172.137.15
- **Result:** Clean — Zendesk International Limited, UK
- **Analyst note:** This IP is clean because it belongs to Zendesk. Blocking it would block all legitimate Zendesk emails. This highlights why IP reputation alone is insufficient for detecting platform-abuse phishing.

### VirusTotal — Domains
- **trans.mailnr.com:** Clean — 0/91 vendors
- **s3.ap-south-1.amazonaws.com:** Clean — 0/91 vendors
- **Analyst note:** All domains clean because they are either legitimate platforms (AWS) or newly used redirect infrastructure. This sample would evade automated TI-based detection entirely — human behavioral analysis is the only detection method.

---

## Comparison With Previous Samples

| | Sample 1 | Sample 2 | Sample 3 |
|--|---------|---------|---------|
| SPF | Fail | Fail | **Pass** |
| DKIM | Absent | Forged/Fail | **Pass** |
| DMARC | None | Fail | **Pass** |
| TI Hit | Clean | VT Flagged | Clean |
| Technique | Basic spoofing | Brand impersonation | Platform abuse |
| Severity | Medium | High | **Critical** |
| Filter Bypass | Partial | Partial | **Complete** |

---

## SOC Response — What I Would Do Next
1. **Report the Zendesk account** (`pcpilrjf.zendesk.com`) to Zendesk abuse team for takedown
2. **Block trans.mailnr.com** at the web proxy
3. **Cannot block the sending IP** — it belongs to Zendesk; blocking would cause collateral damage
4. **Search SIEM** for other emails from `pcpilrjf.zendesk.com`
5. **Check proxy logs** for connections to `trans.mailnr.com` — any hit means potential credential compromise
6. **Escalate immediately** — platform abuse phishing that passes all auth checks requires Tier 2 review
7. **Create detection rule** in SIEM — flag emails from randomly generated Zendesk subdomains

---

## Key Takeaway
This sample demonstrates that authentication checks are necessary but not sufficient for phishing detection. A SOC analyst must combine authentication results, behavioral indicators, geographic anomalies, and threat intelligence to make accurate triage decisions. Automated filters alone would have delivered this email to every inbox.

---

## Tools Used
- Custom Python script (`analyze.py`) — header extraction, spoofing detection, URL parsing, threat intel enrichment
- AbuseIPDB API — sending IP reputation
- VirusTotal API — domain reputation
- Sample source: [phishing_pot](https://github.com/rf-peixoto/phishing_pot)