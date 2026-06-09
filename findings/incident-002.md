# Incident Report 002 — Microsoft Account Impersonation
**Date Analyzed:** June 2026
**Sample Source:** phishing_pot (public phishing repository)
**Severity:** High
**Status:** Analyzed

**Tool Output:** See [sample2_output.txt](sample2_output.txt)

---

## Executive Summary
A phishing email impersonating Microsoft's account security team, using an urgency tactic ("unusual sign-in activity") to trick victims into clicking a malicious link. The email forges a DKIM signature claiming to be from microsoft.com, uses a Reply-To mismatch to redirect victim replies, and delivers a payload through sefnet.net — a domain confirmed malicious by VirusTotal.

---

## Indicators of Compromise (IOCs)

| Type | Value | Verdict |
|------|-------|---------|
| From Domain | microsoft.com | Forged — not the real Microsoft |
| Reply-To Domain | usual-assist.com | Attacker controlled |
| Actual Sending Domain | nisihfjoz.co.uk | Throwaway domain |
| Sending IP | 103.167.154.120 | India — unrelated to Microsoft infrastructure |
| Payload URL | sefnet.net | ⚠️ MALICIOUS — 4/91 vendors on VirusTotal |

---

## Detailed Analysis

### 1. Brand Impersonation
The From header displays `no-reply@microsoft.com` — a legitimate-looking Microsoft address. However the actual sending infrastructure is `nisihfjoz.co.uk` at IP `103.167.154.120` based in India. Microsoft's mail servers are never hosted in India on unknown ISPs. This is a classic brand impersonation attack designed to exploit the victim's trust in Microsoft.

### 2. Urgency Manipulation
The subject line "Microsoft account unusual sign-in activity" is deliberately alarming. This is a social engineering tactic — creating urgency pushes victims to act quickly without thinking critically, making them more likely to click the link without verifying the sender.

### 3. DKIM Forgery Attempt
Unlike sample 1 where DKIM was completely absent, this attacker went further and included a forged DKIM signature claiming to be from `microsoft.com`. However it fails verification because there is no valid public key for that selector in Microsoft's DNS. This shows a more sophisticated attacker who understands email authentication and attempted to bypass it.

### 4. Reply-To Mismatch
The Reply-To header points to `media-protection@usual-assist.com` — completely unrelated to Microsoft. Any victim replying to what they think is a Microsoft security alert would be sending their response directly to the attacker.

### 5. Confirmed Malicious Payload
The payload URL `http://sefnet.net/track/o7436EVFfO5968877utQY8065QJB8855GHAz1` was flagged by 4 malicious and 1 suspicious vendor out of 91 on VirusTotal — confirming this is a known malicious domain. The tracking path structure suggests this is a credential harvesting redirect, likely leading to a fake Microsoft login page.

### 6. Authentication Summary
- **SPF:** None — sending IP not authorized for nisihfjoz.co.uk
- **DKIM:** Fail — forged signature, no valid key found
- **DMARC:** Fail with oreject — policy exists but email still delivered

---

## Threat Intelligence Enrichment

### AbuseIPDB — Sending IP: 103.167.154.120
- **Result:** Clean — No abuse reports
- **Country:** India
- **ISP:** Unknown

**Analyst note:** IP is based in India with an unresolved ISP. Microsoft's legitimate mail infrastructure operates from known US-based data centers. An Indian IP claiming to be Microsoft is a strong geographic anomaly indicator.

### VirusTotal — Domain: sefnet.net
- **Result:** ⚠️ FLAGGED — 4 malicious, 1 suspicious out of 91 vendors

**Analyst note:** This is a confirmed malicious domain. Unlike sample 1 where TI returned clean, this sample produced a real positive hit — demonstrating the value of always checking URLs against threat intel even when other indicators seem moderate.

---

## Comparison with Sample 1
This sample is more sophisticated than the Dutch solar panel phishing email in several ways. It impersonates a globally trusted brand, uses urgency manipulation, attempts DKIM forgery rather than omitting it entirely, and uses a confirmed malicious payload domain. The attack chain is designed to maximize victim trust at every step.

---

## SOC Response — What I Would Do Next
1. **Block sefnet.net** immediately at the web proxy — confirmed malicious
2. **Block sending IP** (103.167.154.120) at the email gateway
3. **Search SIEM** for any other emails from nisihfjoz.co.uk or sefnet.net across the organization
4. **Check proxy logs** for any outbound connections to sefnet.net — if found, treat as potential credential compromise
5. **Escalate** to Tier 2 if any user visited the URL — likely credential harvesting means password reset required
6. **Notify users** — Microsoft will never ask you to verify sign-in activity via an unsolicited email

---

## Tools Used
- Custom Python script (`analyze.py`) — header extraction, spoofing detection, URL parsing, threat intel enrichment
- AbuseIPDB API — sending IP reputation
- VirusTotal API — domain reputation (confirmed malicious hit)
- Sample source: [phishing_pot](https://github.com/rf-peixoto/phishing_pot)