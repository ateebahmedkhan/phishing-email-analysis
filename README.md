# Phishing Email Analysis

A hands-on project where I analyzed a real phishing email sample using a custom Python script. Built as part of my SOC analyst learning path.

---

## What I Did

- Downloaded a real phishing `.eml` sample from a public phishing repository
- Built a Python script from scratch to automate email header analysis
- Manually interpreted the output to identify phishing indicators
- Documented findings in a structured incident report

---

## What the Script Does

The script (`scripts/analyze.py`) takes any `.eml` file and extracts:

- Basic headers (From, Reply-To, Subject, Date)
- Spoofing indicators — flags mismatches between From and Reply-To domains
- Authentication headers — checks SPF, DKIM, DMARC status
- Email routing path via the Received chain
- All URLs found in the email body
- Attachment detection

**Usage:**
```bash
python3 analyze.py <path_to_email.eml>
```

---

## Sample Output & Findings

The sample I analyzed was a Dutch-language solar panel phishing email. Key findings:

| Indicator | Finding |
|-----------|---------|
| SPF | Failed — sending IP not authorized |
| DKIM | Not present — email unsigned |
| DMARC | None — no policy enforced |
| From Domain | appjj.serenitepure.fr |
| Reply-To Domain | aichakandisha.com (mismatch — spoofing) |
| Actual Sending IP | 57.128.69.202 (dturm.de) |
| Payload URL | go.nltrck.com (redirect/tracking link) |

Full analysis in [`findings/incident-001.md`](findings/incident-001.md)

---

## What I Learned

- How SPF, DKIM, and DMARC work together and what their absence means
- How attackers use From/Reply-To mismatches to redirect victims
- How to trace the real origin of an email through the Received chain
- How phishing campaigns use redirect URLs and external image hosting to evade filters
- How to write a structured incident report the way a SOC analyst would

---

## Tools Used

- Python 3 (standard library only — `email`, `re`, `urllib`)
- Real phishing sample from [phishing_pot](https://github.com/rf-peixoto/phishing_pot)

---

## Repository Structure
