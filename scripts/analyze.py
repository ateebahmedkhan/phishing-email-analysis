import email
import sys
import re
import json
import urllib.request
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")
VT_API_KEY    = os.getenv("VT_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")

def check_virustotal(domain):
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        req = urllib.request.Request(url, headers={"x-apikey": VT_API_KEY})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read())
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        if malicious > 0 or suspicious > 0:
            return f"⚠️  FLAGGED — {malicious} malicious, {suspicious} suspicious out of {total} vendors"
        else:
            return f"✅  Clean — 0 detections out of {total} vendors"
    except Exception as e:
        return f"Could not retrieve VirusTotal data: {e}"


def check_abuseipdb(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "Key": ABUSEIPDB_KEY,
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read())
        d = data["data"]
        score = d["abuseConfidenceScore"]
        reports = d["totalReports"]
        country = d.get("countryCode", "Unknown")
        isp = d.get("isp", "Unknown")
        if score > 0:
            return f"⚠️  FLAGGED — Abuse score: {score}/100, Reports: {reports}, Country: {country}, ISP: {isp}"
        else:
            return f"✅  Clean — No reports, Country: {country}, ISP: {isp}"
    except Exception as e:
        return f"Could not retrieve AbuseIPDB data: {e}"


def analyze_email(filepath):
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    print("=" * 60)
    print("PHISHING EMAIL ANALYSIS REPORT")
    print("=" * 60)

    # --- Basic Headers ---
    print("\n[1] BASIC HEADERS")
    print(f"  From       : {msg.get('From')}")
    print(f"  Reply-To   : {msg.get('Reply-To')}")
    print(f"  To         : {msg.get('To')}")
    print(f"  Subject    : {msg.get('Subject')}")
    print(f"  Date       : {msg.get('Date')}")

    # --- Spoofing Check ---
    print("\n[2] SPOOFING INDICATORS")
    from_header = str(msg.get('From', ''))
    reply_to = str(msg.get('Reply-To', ''))

    from_domain = re.findall(r'@([\w\.\-]+)', from_header)
    reply_domain = re.findall(r'@([\w\.\-]+)', reply_to)

    if from_domain:
        print(f"  From Domain    : {from_domain[0]}")
    if reply_domain:
        print(f"  Reply-To Domain: {reply_domain[0]}")
    if from_domain and reply_domain and from_domain[0] != reply_domain[0]:
        print("  ⚠️  MISMATCH: From and Reply-To domains are different — spoofing indicator")
    else:
        print("  From and Reply-To domains match (or Reply-To absent)")

    # --- Authentication Headers ---
    print("\n[3] AUTHENTICATION HEADERS")
    for header in ['Received-SPF', 'Authentication-Results', 'DKIM-Signature', 'ARC-Authentication-Results']:
        val = msg.get(header)
        if val:
            print(f"  {header}: {val[:120]}")
        else:
            print(f"  {header}: NOT PRESENT")

    # --- Received Chain ---
    print("\n[4] RECEIVED CHAIN (email routing path)")
    received = msg.get_all('Received') or []
    sending_ip = None
    for i, hop in enumerate(received):
        print(f"  Hop {i+1}: {hop.strip()[:120]}")
        ip_match = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', hop)
        for ip in ip_match:
            if not ip.startswith(('10.', '172.', '192.168.', '127.')):
                sending_ip = ip
                break

    # --- URL Extraction ---
    print("\n[5] URLS FOUND IN BODY")
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ['text/plain', 'text/html']:
                try:
                    body += part.get_content()
                except:
                    pass
    else:
        try:
            body = msg.get_content()
        except:
            pass

    urls = re.findall(r'https?://[^\s"<>]+', body)
    unique_domains = set()
    if urls:
        for url in set(urls):
            parsed = urlparse(url)
            print(f"  URL    : {url[:100]}")
            print(f"  Domain : {parsed.netloc}")
            if parsed.netloc and 'imgur.com' not in parsed.netloc:
                unique_domains.add(parsed.netloc)
            print()
    else:
        print("  No URLs found in body")

    # --- Attachment Check ---
    print("\n[6] ATTACHMENTS")
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            attachments.append(part.get_filename())
    if attachments:
        for a in attachments:
            print(f"  ⚠️  Attachment found: {a}")
    else:
        print("  No attachments found")

    # --- Threat Intelligence ---
    print("\n[7] THREAT INTELLIGENCE ENRICHMENT")

    if sending_ip:
        print(f"\n  AbuseIPDB — Sending IP: {sending_ip}")
        print(f"  {check_abuseipdb(sending_ip)}")
    else:
        print("  Could not extract sending IP automatically")

    if unique_domains:
        print(f"\n  VirusTotal — Suspicious Domains:")
        for domain in unique_domains:
            vt_result = check_virustotal(domain)
            print(f"  Domain : {domain}")
            print(f"  Result : {vt_result}")
    else:
        print("\n  No suspicious domains to check on VirusTotal")

    print("\n" + "=" * 60)
    print("END OF REPORT")
    print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze.py <path_to_eml_file>")
    else:
        analyze_email(sys.argv[1])