#!/usr/bin/env python3
"""
Email Phishing Detector
Scans email content for common phishing indicators.
Usage: python phishing_detector.py <email_file.txt>
"""

import re
import sys
import argparse
from urllib.parse import urlparse
from colorama import init
init()

# ─────────────────────────────────────────────
# INDICATOR DEFINITIONS
# ─────────────────────────────────────────────

URGENT_WORDS = [
    "urgent", "immediately", "action required", "act now", "right away",
    "verify now", "confirm now", "suspended", "limited time", "expires soon",
    "final notice", "last chance", "critical", "warning", "alert",
    "your account will be", "account compromised", "unauthorized access",
    "click here now", "respond immediately", "failure to respond",
    "within 24 hours", "within 48 hours", "as soon as possible","asap"
]

SUSPICIOUS_DOMAINS = [
    ".xyz", ".top", ".club", ".click", ".link", ".online", ".site",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc",
]

COMMON_LEGIT_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "instagram", "netflix", "bank", "chase", "wellsfargo", "citibank",
    "irs", "fedex", "ups", "dhl", "usps", "ebay",
]

LOOKALIKE_PATTERNS = [
    (r'pay[-_.]?pal', 'PayPal'),
    (r'amaz[o0]n', 'Amazon'),
    (r'g[o0]{2}gle', 'Google'),
    (r'micr[o0]s[o0]ft', 'Microsoft'),
    (r'app1e|appl[e3]', 'Apple'),
    (r'faceb[o0]{2}k', 'Facebook'),
    (r'netfl[i1]x', 'Netflix'),
    (r'[i1]rs\.', 'IRS'),
]


# ─────────────────────────────────────────────
# DETECTION FUNCTIONS
# ─────────────────────────────────────────────

def extract_urls(text: str) -> list:
    url_pattern = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+')
    return url_pattern.findall(text)


def check_suspicious_links(text: str) -> list:
    findings = []
    urls = extract_urls(text)
    for url in urls:
        reasons = []
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        host = parsed.hostname or ''

        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            reasons.append("IP address used instead of domain name")

        for tld in SUSPICIOUS_DOMAINS:
            if host.endswith(tld):
                reasons.append(f"Suspicious TLD: {tld}")

        parts = host.split('.')
        if len(parts) > 2:
            subdomain = '.'.join(parts[:-2])
            for brand in COMMON_LEGIT_BRANDS:
                if brand in subdomain.lower():
                    reasons.append(f"Brand '{brand}' in subdomain (possible spoofing)")

        domain_str = host.replace('-', '').replace('_', '')
        for pattern, brand in LOOKALIKE_PATTERNS:
            if re.search(pattern, domain_str, re.IGNORECASE):
                if brand.lower() not in host.lower().split('.'):
                    reasons.append(f"Lookalike domain impersonating {brand}")

        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
                      'buff.ly', 'is.gd', 'rebrand.ly', 'short.link']
        if any(s in host for s in shorteners):
            reasons.append("URL shortener detected (hides real destination)")

        if '%' in url and url.count('%') > 3:
            reasons.append("Heavily encoded URL (possible obfuscation)")

        if reasons:
            findings.append({
                "url": url[:80] + ("..." if len(url) > 80 else ""),
                "reasons": reasons
            })
    return findings


def check_urgent_language(text: str) -> list:
    text_lower = text.lower()
    return [p for p in URGENT_WORDS if p in text_lower]


def check_spoofed_sender(text: str) -> list:
    findings = []
    from_pattern = re.compile(r'(?:From|Reply-To)\s*:\s*(.+)', re.IGNORECASE)
    for header in from_pattern.findall(text):
        issues = []
        email_match = re.search(r'[\w.+-]+@([\w.-]+)', header)
        if not email_match:
            continue
        domain = email_match.group(1).lower()

        for pattern, brand in LOOKALIKE_PATTERNS:
            domain_clean = domain.replace('-', '').replace('_', '')
            if re.search(pattern, domain_clean, re.IGNORECASE):
                issues.append(f"Sender domain may impersonate {brand}")

        if domain.count('-') >= 2:
            issues.append("Domain contains multiple hyphens (suspicious)")

        display_name = header[:header.rfind('<')].strip().lower() if '<' in header else ''
        for brand in COMMON_LEGIT_BRANDS:
            if brand in display_name and brand not in domain:
                issues.append(f"Display name mentions '{brand}' but domain doesn't match")
                break

        if issues:
            findings.append({"header": header.strip(), "issues": issues})
    return findings


def check_generic_greeting(text: str) -> bool:
    pattern = re.compile(
        r'\b(dear\s+(customer|user|member|account holder|sir|madam|valued customer))\b',
        re.IGNORECASE
    )
    return bool(pattern.search(text))


def check_credential_requests(text: str) -> list:
    patterns = [
        (r'(enter|provide|confirm|update|verify)\s+your\s+(password|pin|ssn|social security)',
         "Requests password/PIN/SSN"),
        (r'(credit card|card number|cvv|expiry date)', "References credit card details"),
        (r'(bank\s+account|routing\s+number|account\s+number)', "Requests bank account details"),
        (r'(social\s+security|taxpayer\s+id)', "Requests Social Security / Tax ID"),
    ]
    text_lower = text.lower()
    return [label for pat, label in patterns if re.search(pat, text_lower)]


# ─────────────────────────────────────────────
# SCORING & REPORT
# ─────────────────────────────────────────────

def calculate_risk(results: dict):
    score = 0
    score += len(results["suspicious_links"]) * 3
    score += len(results["urgent_phrases"]) * 1
    score += len(results["spoofed_senders"]) * 4
    score += 2 if results["generic_greeting"] else 0
    score += len(results["credential_requests"]) * 3

    if score >= 8:
        return "HIGH", score
    elif score >= 4:
        return "MEDIUM", score
    elif score >= 1:
        return "LOW", score
    else:
        return "NONE", score


def print_report(results: dict, filename: str):
    risk_level, score = calculate_risk(results)

    verdict = {
        "HIGH":   "LIKELY PHISHING",
        "MEDIUM": "POSSIBLY PHISHING",
        "LOW":    "SUSPICIOUS (Low Confidence)",
        "NONE":   "LIKELY SAFE",
    }.get(risk_level, "UNKNOWN")

    print(f"\n{'='*58}")
    print(f"  EMAIL PHISHING DETECTOR  |  {filename}")
    print(f"{'='*58}")
    print(f"  Verdict : {verdict}")
    print(f"  Risk    : {risk_level}  (score: {score})")
    print(f"{'-'*58}")

    if results["suspicious_links"]:
        print(f"\n  Suspicious Links ({len(results['suspicious_links'])} found)")
        for item in results["suspicious_links"]:
            print(f"     URL: {item['url']}")
            for r in item["reasons"]:
                print(f"       -> {r}")
    else:
        print(f"\n  No suspicious links detected.")

    if results["urgent_phrases"]:
        print(f"\n  Urgent Language ({len(results['urgent_phrases'])} phrase(s))")
        for p in results["urgent_phrases"]:
            print(f'     * "{p}"')
    else:
        print(f"\n  No urgent language detected.")

    if results["spoofed_senders"]:
        print(f"\n  Suspicious Sender(s)")
        for item in results["spoofed_senders"]:
            print(f"     Header: {item['header']}")
            for issue in item["issues"]:
                print(f"       -> {issue}")
    else:
        print(f"\n  No spoofed sender detected.")

    if results["generic_greeting"]:
        print(f"\n  Generic greeting detected (no recipient name used)")

    if results["credential_requests"]:
        print(f"\n  Sensitive Info Requested")
        for c in results["credential_requests"]:
            print(f"     * {c}")

    print(f"\n{'='*58}\n")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def analyze_email(text: str) -> dict:
    return {
        "suspicious_links":    check_suspicious_links(text),
        "urgent_phrases":      check_urgent_language(text),
        "spoofed_senders":     check_spoofed_sender(text),
        "generic_greeting":    check_generic_greeting(text),
        "credential_requests": check_credential_requests(text),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Email Phishing Detector - scan an email .txt file for phishing indicators."
    )
    parser.add_argument("email_file", help="Path to the .txt file containing email content")
    args = parser.parse_args()

    try:
        with open(args.email_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.email_file}' not found.")
        sys.exit(1)

    results = analyze_email(content)
    print_report(results, args.email_file)


if __name__ == "__main__":
    main()