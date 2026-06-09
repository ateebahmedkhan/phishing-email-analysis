# Incident Report 001 — Dutch Solar Panel Phishing Campaign
**Date Analyzed:** June 2026
**Sample Source:** phishing_pot (public phishing repository)
**Severity:** Medium
**Status:** Analyzed

**Tool Output:** See [sample1_output.png](sample1_output.png) and [sample-output.txt](sample-output.txt)

---

## Executive Summary
A phishing email disguised as a Dutch solar panel promotional offer targeting Dutch-speaking recipients. The email uses domain spoofing, completely absent email authentication, a redirect tracking URL, and external image hosting to evade filters. Threat intelligence enrichment via AbuseIPDB and VirusTotal was performed on the sending IP and suspicious domain.

---

## Indicators of Compromise (IOCs)

| Type | Value | Verdict |
|------|-------|---------|
| From Domain | appjj.serenitepure.fr | Spoofed |
| Reply-To Domain | aichakandisha.com | Attacker controlled |
| Actual Sending Domain | dturm.de | Header forgery |
| Sending IP | 57.128.69.202 | Clean on AbuseIPDB — OVH SAS, France (high-risk ISP) |
| Redirect URL | go.nltrck.com | Clean on VirusTotal — behavioral indicators present |

---

## Detailed Analysis

### 1. Domain Spoofing
The `From` header displays `appjj.serenitepure.fr` while the `Reply-To` header points to `aichakandisha.com` — completely unrelated domains. Any victim replying to this email would contact the attacker's controlled domain instead of the apparent sender. This is a classic technique used to harvest replies and redirect victims.

### 2. Authentication Failures — SPF, DKIM, DMARC
All three email authentication mechanisms failed completely:
- **SPF:** None — the sending IP `57.128.69.202` is not authorized to send on behalf of `dturm.de`
- **DKIM:** Not present — the email carries no cryptographic signature, meaning it cannot be verified as untampered
- **DMARC:** None — no policy is defined, so no enforcement or reporting action is taken

Legitimate bulk senders always configure at least SPF and DKIM. The complete absence of all three is one of the strongest phishing indicators.

### 3. Header Forgery
The Received chain shows the email originated from `dturm.de` (IP: `57.128.69.202`) — a domain that appears in none of the visible From or Reply-To headers. The attacker used a separate sending infrastructure while forging the display headers to appear as a legitimate French solar panel company.

### 4. Redirect Payload
The only non-image URL in the body is: http://go.nltrck.com/?c=495&source=consumentenbond&s1=&lp=1190

This is an affiliate tracking redirect. The parameters (`c=495`, `lp=1190`) suggest a campaign ID and landing page ID — typical of phishing operations monetized through affiliate marketing. The redirect obscures the final destination from email content filters.

### 5. Image Hosting Evasion
All images are hosted externally on Imgur rather than embedded inline. This keeps the email body lightweight and free of suspicious binary content, making it harder for content-based spam filters to flag it.

---

## Threat Intelligence Enrichment

### AbuseIPDB — Sending IP: 57.128.69.202
- **Result:** Clean — No abuse reports in last 90 days
- **Country:** France
- **ISP:** OVH SAS

**Analyst note:** OVH SAS is a French hosting provider frequently abused for spam and phishing campaigns due to its low-cost infrastructure. A clean AbuseIPDB score does not indicate a legitimate sender — it means the IP has not yet been reported. This highlights a key limitation of reactive threat intel: databases lag behind active campaigns.

### VirusTotal — Domain: go.nltrck.com
- **Result:** 0 detections out of 91 vendors

**Analyst note:** The domain returned clean on VirusTotal, which is common for newly registered or short-lived redirect domains used in active phishing campaigns. In a real SOC environment, this domain would still be flagged for manual review based on behavioral indicators — unencrypted HTTP, affiliate tracking parameters, and presence in a phishing email chain.

---

## SOC Response — What I Would Do Next

In a real SOC environment, the following actions would be taken:

1. **Block the sending IP** (`57.128.69.202`) at the email gateway
2. **Block the redirect domain** (`go.nltrck.com`) at the web proxy/firewall
3. **Search SIEM** for other emails from the same IP or domain across the organization
4. **Submit IOCs** to internal threat intel platform and flag for the team
5. **Check proxy logs** for any users who clicked the redirect link — look for outbound connections to `go.nltrck.com`
6. **Notify affected mailbox owner** and send phishing awareness reminder

---

## Tool Limitations
- Script extracts the first public IP from the Received chain — may not always identify true origin in complex routing scenarios
- VirusTotal and AbuseIPDB results are point-in-time — a clean result does not confirm legitimacy
- URL extraction uses regex — may miss obfuscated or encoded URLs in HTML bodies

---

## Tools Used
- Custom Python script (`analyze.py`) — header extraction, spoofing detection, URL parsing, threat intel enrichment
- AbuseIPDB API — sending IP reputation check
- VirusTotal API — domain reputation check
- Sample source: [phishing_pot](https://github.com/rf-peixoto/phishing_pot)