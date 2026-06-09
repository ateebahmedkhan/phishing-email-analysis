import email
import sys
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

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
    for i, hop in enumerate(received):
        print(f"  Hop {i+1}: {hop.strip()[:120]}")

    # --- URL Extraction ---
    print("\n[5] URLS FOUND IN BODY")
    urls = []
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ['text/plain', 'text/html']:
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
    if urls:
        for url in set(urls):
            parsed = urlparse(url)
            print(f"  URL    : {url[:100]}")
            print(f"  Domain : {parsed.netloc}")
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

    print("\n" + "=" * 60)
    print("END OF REPORT")
    print("=" * 60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze.py <path_to_eml_file>")
    else:
        analyze_email(sys.argv[1])
