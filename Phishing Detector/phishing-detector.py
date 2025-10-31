#!/usr/bin/env python3
"""
phishing_detector.py

Simple regex-based scanner that inspects an email (plain text or raw HTML)
for common phishing indicators and prints a human-readable report.

Usage:
    python phishing_detector.py --file email.txt
    python phishing_detector.py   # paste input, then EOF (Ctrl+D / Ctrl+Z)

No external libraries required.
"""

import argparse
import re
import sys
from typing import List, Tuple, Dict

# --- Heuristics / signature lists ---
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "info", "online", "site", "bid", "loan", "click", "work", "gq", "pw"
}
CREDENTIAL_KEYWORDS = {
    "verify", "verification", "confirm", "confirm your", "update", "reset", "password", "credentials",
    "login", "sign in", "account suspended", "account will be suspended", "urgent", "immediately",
    "click here", "provide", "submit", "bank", "billing", "invoice"
}
SUSPICIOUS_PHRASES = {
    "your account has been", "we detected unusual activity", "suspicious login", "security alert",
    "unauthorized", "update your payment", "verify your identity"
}

# URL regex (simplified, works for most common cases)
URL_RE = re.compile(
    r"(?P<url>(?:http[s]?://|ftp://|www\.)"               # scheme or www
    r"(?:[^\s/$.?#].[^\s]*)"                              # domain and path
    r")", re.IGNORECASE
)

# Email regex
EMAIL_RE = re.compile(r"(?P<email>[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})")

# Anchor tag regex (very small HTML heuristic to find <a ...>text</a>)
ANCHOR_RE = re.compile(r"<a\s+[^>]*href=[\"'](?P<href>[^\"']+)[\"'][^>]*>(?P<text>.*?)</a>", re.IGNORECASE | re.DOTALL)

# Detect IP-based domain in URL (http://123.45.67.89/...)
IP_DOMAIN_RE = re.compile(r"https?://(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:/|$)")

# user:pass@ in URL
CREDENTIAL_IN_URL_RE = re.compile(r"https?://[^/@]+@[^/]+")

# punycode / xn-- domain
PUNYCODE_RE = re.compile(r"xn--")

# long URL heuristic
LONG_URL_LEN = 100


# --- Extraction helpers ---
def extract_urls(text: str) -> List[str]:
    return [m.group("url") for m in URL_RE.finditer(text)]


def extract_emails(text: str) -> List[str]:
    return [m.group("email") for m in EMAIL_RE.finditer(text)]


def extract_anchor_pairs(html_text: str) -> List[Tuple[str, str]]:
    """Return list of (href, visible_text) for anchor tags found (if any)."""
    return [(m.group("href").strip(), sanitize_text(m.group("text").strip())) for m in ANCHOR_RE.finditer(html_text)]


def sanitize_text(s: str, max_len: int = 80) -> str:
    s = re.sub(r"\s+", " ", s)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


# --- Indicator functions ---
def is_ip_based(url: str) -> bool:
    return bool(IP_DOMAIN_RE.search(url))


def has_credentials_in_url(url: str) -> bool:
    return bool(CREDENTIAL_IN_URL_RE.search(url))


def has_punycode(url: str) -> bool:
    return bool(PUNYCODE_RE.search(url))


def suspicious_tld(url: str) -> bool:
    # Extract TLD and check against suspicious set
    m = re.search(r"\.([a-zA-Z]{2,63})(?:[:/]|$)", url)
    if not m:
        return False
    tld = m.group(1).lower()
    return tld in SUSPICIOUS_TLDS


def long_url(url: str) -> bool:
    return len(url) > LONG_URL_LEN


def url_has_at_sign_in_path(url: str) -> bool:
    # presence of '@' in path (after domain) can be obfuscation or credential-like
    return "@" in re.sub(r"^[^/]+//", "", url)  # remove scheme so we inspect domain+path


def contains_credential_request(text: str) -> Tuple[bool, List[str]]:
    found = []
    low = text.lower()
    for kw in CREDENTIAL_KEYWORDS:
        if kw in low:
            found.append(kw)
    return (len(found) > 0, found)


def contains_suspicious_phrases(text: str) -> Tuple[bool, List[str]]:
    found = []
    low = text.lower()
    for ph in SUSPICIOUS_PHRASES:
        if ph in low:
            found.append(ph)
    return (len(found) > 0, found)


# --- Scoring / report generation ---
def analyze_text(text: str) -> Dict:
    urls = extract_urls(text)
    emails = extract_emails(text)
    anchors = extract_anchor_pairs(text)

    issues = []
    score_penalty = 0

    # Check emails
    if emails:
        unique_emails = sorted(set(emails))
    else:
        unique_emails = []

    # URLs analysis
    url_findings = []
    for u in urls:
        flags = []
        if is_ip_based(u):
            flags.append("IP-based URL")
            score_penalty += 20
        if has_credentials_in_url(u):
            flags.append("credentials in URL")
            score_penalty += 30
        if has_punycode(u):
            flags.append("punycode/xn--")
            score_penalty += 20
        if suspicious_tld(u):
            flags.append("suspicious TLD")
            score_penalty += 15
        if long_url(u):
            flags.append("very long URL")
            score_penalty += 5
        if url_has_at_sign_in_path(u):
            flags.append("'@' in URL path")
            score_penalty += 10

        url_findings.append({"url": u, "flags": flags})

    # Anchor mismatches (HTML)
    anchor_findings = []
    for href, text_visible in anchors:
        # normalize visible text that looks like a URL
        visible_lower = text_visible.lower()
        href_lower = href.lower()
        mismatch = False
        # If visible text contains a domain or url-like pattern but differs from href domain, mark mismatch
        if re.search(r"(https?://|www\.|\.)", visible_lower):
            # extract domains
            dom_vis = extract_domain_from_any(visible_lower)
            dom_href = extract_domain_from_any(href_lower)
            if dom_vis and dom_href and dom_vis != dom_href:
                mismatch = True
        if mismatch:
            anchor_findings.append({"href": href, "visible_text": text_visible, "issue": "display text differs from link (potential obfuscation)"})
            score_penalty += 25

    # Keyword/phrase checks
    cred_req, cred_list = contains_credential_request(text)
    if cred_req:
        issues.append({"type": "credential_request", "matches": cred_list})
        score_penalty += 20

    susp_phr, susp_list = contains_suspicious_phrases(text)
    if susp_phr:
        issues.append({"type": "suspicious_phrase", "matches": susp_list})
        score_penalty += 10

    # If there are many unusual URLs, raise suspicion
    if len(urls) >= 5:
        issues.append({"type": "many_urls", "count": len(urls)})
        score_penalty += 10

    # If no sender email found (heuristic)
    found_from_header = re.search(r"^From:\s*(.*)$", text, re.IGNORECASE | re.MULTILINE)
    if not found_from_header:
        issues.append({"type": "no_from_header_detected"})
        score_penalty += 5
    else:
        # try to detect mismatch between display name and email domain
        from_line = found_from_header.group(1).strip()
        # find email in from line
        m = EMAIL_RE.search(from_line)
        if m:
            from_email = m.group("email")
            display_part = re.sub(r"<[^>]+>", "", from_line).replace(from_email, "").strip().strip('"').strip()
            # if display contains a domain-like token different from email domain, flag it (weak heuristic)
            dom_email = extract_domain_from_any(from_email)
            dom_display = extract_domain_from_any(display_part)
            if dom_display and dom_email and dom_display != dom_email:
                issues.append({"type": "from_display_mismatch", "from": from_line})
                score_penalty += 15

    # Compose risk score (100 = clean, lower = more suspicious)
    base_score = 100
    risk_score = max(0, base_score - score_penalty)

    report = {
        "risk_score": risk_score,
        "urls": url_findings,
        "anchors": anchor_findings,
        "emails": unique_emails,
        "issues": issues,
        "summary": generate_summary(risk_score, url_findings, anchor_findings, issues),
    }
    return report


def extract_domain_from_any(s: str) -> str:
    """
    Try to extract just the domain (host) from a URL or a text that contains domain.
    Returns lowercased domain or empty string.
    """
    if not s:
        return ""
    # try URL pattern
    m = re.search(r"(?:https?://)?(?:www\.)?([^/:>\s]+)", s)
    if m:
        return m.group(1).lower()
    return ""


def generate_summary(risk_score: int, url_findings: List[Dict], anchor_findings: List[Dict], issues: List[Dict]) -> str:
    if risk_score >= 85:
        return "Low risk (minor or no suspicious indicators detected)."
    if 60 <= risk_score < 85:
        return "Medium risk (some suspicious indicators present; review carefully)."
    if 30 <= risk_score < 60:
        return "High risk (multiple indicators suggest phishing)."
    return "Very high risk (strong signs of phishing)."


# --- Reporting / output ---
def print_report(report: Dict):
    print("\n==== Phishing Detector Report ====\n")
    print(f"Risk score: {report['risk_score']}/100")
    print(f"Summary: {report['summary']}\n")

    if report["emails"]:
        print("Found email addresses:")
        for e in report["emails"]:
            print(f" - {e}")
        print("")

    if report["urls"]:
        print(f"Found {len(report['urls'])} URLs:")
        for u in report["urls"]:
            flags = u["flags"]
            flag_str = ", ".join(flags) if flags else "none"
            print(f" - {u['url']}  -> {flag_str}")
        print("")

    if report["anchors"]:
        print("Suspicious anchor tag mismatches:")
        for a in report["anchors"]:
            print(f" - HREF: {a['href']}")
            print(f"   Visible text: {a['visible_text']}")
            print(f"   Issue: {a['issue']}\n")

    if report["issues"]:
        print("Other issues detected:")
        for it in report["issues"]:
            # pretty print dict-like issues
            if isinstance(it, dict):
                parts = [f"{k}: {v}" for k, v in it.items()]
                print(" - " + "; ".join(parts))
            else:
                print(f" - {it}")
        print("")

    print("Recommendations:")
    recs = [
        "Do NOT click links or download attachments from this email until verified.",
        "If the email requests credentials, contact the organization by using a known-good phone number or website.",
        "Check sender address carefully — don't trust display names alone.",
        "Hover over links (in a safe environment) to confirm destination domain before clicking.",
        "Report suspected phishing to your security team or provider."
    ]
    for r in recs:
        print(f" - {r}")
    print("\n==================================\n")


# --- CLI ---
def main():
    parser = argparse.ArgumentParser(description="Simple Email Phishing Detector (regex heuristics)")
    parser.add_argument("--file", "-f", help="Path to file containing email or text to scan")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # read stdin
        if sys.stdin.isatty():
            print("Paste the email/text, then press Ctrl+D (Linux/macOS) or Ctrl+Z then Enter (Windows) to finish:")
        text = sys.stdin.read()

    if not text:
        print("No input provided. Exiting.", file=sys.stderr)
        sys.exit(1)

    report = analyze_text(text)
    print_report(report)


if __name__ == "__main__":
    main()

