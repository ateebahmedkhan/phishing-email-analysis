# Incident Report — Phishing Email Analysis
**Date Analyzed:** 2025  
**Sample:** Dutch solar panel phishing email  
**Severity:** Medium  

---

## Summary
A phishing email disguised as a solar panel promotional offer, targeting Dutch-speaking recipients. The email uses domain spoofing, missing email authentication, and a redirect URL to deceive victims.

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| From Domain | appjj.serenitepure.fr |
| Reply-To Domain | aichakandisha.com |
| Sending IP | 57.128.69.202 |
| Actual Sending Domain | dturm.de |
| Redirect URL | go.nltrck.com |

---

## Analysis

### 1. Domain Spoofing
The `From` header shows `appjj.serenitepure.fr` while the `Reply-To` header points to `aichakandisha.com`. These are completely different domains with no relation to each other. Any victim replying would contact the attacker's controlled domain, not the apparent sender.

### 2. Authentication Failures
All three email authentication mechanisms failed:
- **SPF:** None — the sending IP is not authorized to send on behalf of the domain
- **DKIM:** Not present — the email is unsigned, meaning it cannot be verified as legitimate
- **DMARC:** None — no policy defined, so no enforcement action is taken

Legitimate marketing emails always have SPF and DKIM configured. The complete absence of all three is a strong phishing indicator.

### 3. Header Forgery
The Received chain shows the email actually originated from `dturm.de` (IP: 57.128.69.202) — a domain that appears in none of the visible From/Reply-To headers. This mismatch between the actual sending infrastructure and the displayed headers indicates deliberate header manipulation.

### 4. Redirect Payload
The only non-image URL in the body is `go.nltrck.com` with affiliate tracking parameters. This is a redirect chain used to obscure the final destination from email filters while tracking victim clicks for affiliate monetization.

### 5. Image Hosting Evasion
All images are hosted on Imgur rather than inline. This keeps the email body clean to evade content-based spam filters.

---

## Conclusion
This email exhibits five distinct phishing indicators: domain spoofing, SPF/DKIM/DMARC failures, header forgery, redirect payload, and image evasion techniques. A real SOC analyst would flag this email, block the sending IP, and submit the redirect domain to a threat intelligence platform like VirusTotal or AbuseIPDB.

---

## Tools Used
- Custom Python script (analyze.py) for header extraction and URL parsing
- Manual header chain analysis
