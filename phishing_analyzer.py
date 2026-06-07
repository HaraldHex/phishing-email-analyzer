#!/usr/bin/env python3
"""
phishing_analyzer.py

A simple SOC tool that triages a suspicious e-mail (.eml) the way a Tier-1
analyst would: it checks the authentication results, looks for sender
spoofing, extracts and defangs URLs and attachments, scans for social-
engineering cues, and prints a weighted verdict with the reasons behind it.

It also lists the indicators of compromise (IOCs) it found, so they can be
fed straight into an IOC-enrichment lookup.

MITRE ATT&CK mapping: T1566 - Phishing

Usage
-----
  python phishing_analyzer.py sample_phishing.eml
  python phishing_analyzer.py legitimate.eml --json report.json
"""

import argparse
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

# Attachment extensions commonly used to deliver malware.
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".ps1", ".jar", ".lnk", ".iso", ".img", ".html", ".htm",
    ".hta", ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".gz",
}

# Words and phrases frequently used to create urgency or fear in phishing.
URGENCY_TERMS = [
    "urgent", "immediately", "verify your account", "suspended", "limited",
    "unauthorized", "confirm your", "act now", "within 24 hours", "final notice",
    "your account will be", "click here", "log in to avoid", "security alert",
    "unusual activity", "password expires", "validate", "reactivate",
]

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
HREF_RE = re.compile(r"href\s*=\s*[\"']?(https?://[^\"'>\s]+)", re.IGNORECASE)
IP_URL_RE = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly"}


def domain_of(address):
    """Return the lowercased domain part of an e-mail address, or ''."""
    if address and "@" in address:
        return address.rsplit("@", 1)[1].strip(">").lower()
    return ""


def defang(value):
    """Make a URL/domain safe to display and copy without accidental clicks."""
    return value.replace("http", "hxxp").replace(".", "[.]")


def get_bodies(msg):
    """Return (plain_text, html_text) from the message, skipping attachments."""
    plain, html = "", ""
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            continue
        if not isinstance(content, str):
            continue
        if ctype == "text/plain":
            plain += content
        elif ctype == "text/html":
            html += content
    return plain, html


def get_attachments(msg):
    out = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            name = part.get_filename() or "(unnamed)"
            ext = ""
            if "." in name:
                ext = "." + name.rsplit(".", 1)[1].lower()
            out.append({"filename": name, "extension": ext,
                        "risky": ext in RISKY_EXTENSIONS})
    return out


def parse_auth_results(msg):
    """Pull spf / dkim / dmarc verdicts out of the Authentication-Results header."""
    raw = " ".join(msg.get_all("Authentication-Results", []))
    raw += " " + " ".join(msg.get_all("Received-SPF", []))
    raw = raw.lower()
    results = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}\s*=\s*(\w+)", raw)
        results[mech] = m.group(1) if m else "none"
    return results


def analyze(msg):
    findings = []   # list of (points, reason)
    score = 0

    def flag(points, reason):
        nonlocal score
        score += points
        findings.append((points, reason))

    # --- Sender / header analysis ------------------------------------------
    from_name, from_addr = parseaddr(msg["From"] or "")
    _, reply_addr = parseaddr(msg["Reply-To"] or "")
    _, return_addr = parseaddr(msg["Return-Path"] or "")
    from_dom = domain_of(from_addr)
    reply_dom = domain_of(reply_addr)
    return_dom = domain_of(return_addr)

    auth = parse_auth_results(msg)
    if auth["spf"] in ("fail", "softfail"):
        flag(2, f"SPF check did not pass (spf={auth['spf']})")
    if auth["dkim"] in ("fail", "none"):
        flag(2, f"DKIM not validated (dkim={auth['dkim']})")
    if auth["dmarc"] == "fail":
        flag(3, "DMARC failed - message not authorised for the From domain")

    if return_dom and from_dom and return_dom != from_dom:
        flag(2, f"Return-Path domain ({return_dom}) differs from From domain ({from_dom})")
    if reply_dom and from_dom and reply_dom != from_dom:
        flag(2, f"Reply-To domain ({reply_dom}) differs from From domain ({from_dom})")

    # Display-name impersonation: a brand word in the name but a mismatched domain.
    brands = ["paypal", "microsoft", "apple", "amazon", "google", "bank",
              "netflix", "dnb", "posten", "vipps", "skatteetaten"]
    lname = (from_name or "").lower()
    for b in brands:
        if b in lname and b not in from_dom:
            flag(3, f"Display name mentions \"{b}\" but the domain is {from_dom or 'unknown'}")
            break

    # --- Body / social-engineering cues ------------------------------------
    plain, html = get_bodies(msg)
    body = (plain + " " + html).lower()
    subject = (msg["Subject"] or "")
    hit_terms = sorted({t for t in URGENCY_TERMS if t in body or t in subject.lower()})
    if hit_terms:
        pts = min(3, len(hit_terms))
        flag(pts, f"Urgency / social-engineering language: {', '.join(hit_terms[:5])}")

    # --- URLs ---------------------------------------------------------------
    urls = set(URL_RE.findall(plain)) | set(HREF_RE.findall(html))
    urls |= set(URL_RE.findall(html))
    urls = {u.rstrip(".,);\"'") for u in urls}
    for u in urls:
        if IP_URL_RE.match(u):
            flag(3, f"Link points to a raw IP address: {defang(u)}")
        host = re.sub(r"https?://", "", u).split("/")[0].lower()
        if host in SHORTENERS:
            flag(2, f"Link uses a URL shortener: {host}")

    # Link text vs destination mismatch (classic phishing tell).
    anchor_re = re.compile(
        r"<a\s+[^>]*href\s*=\s*[\"']?(https?://[^\"'>\s]+)[^>]*>(.*?)</a>",
        re.IGNORECASE | re.DOTALL,
    )
    for href, text in anchor_re.findall(html):
        shown = URL_RE.findall(text)
        if shown:
            shown_host = re.sub(r"https?://", "", shown[0]).split("/")[0].lower()
            real_host = re.sub(r"https?://", "", href).split("/")[0].lower()
            if shown_host and real_host and shown_host != real_host:
                flag(3, f"Displayed link ({shown_host}) does not match destination ({real_host})")

    # --- Attachments --------------------------------------------------------
    attachments = get_attachments(msg)
    for a in attachments:
        if a["risky"]:
            flag(3, f"Risky attachment type: {a['filename']}")

    # --- Verdict ------------------------------------------------------------
    if score >= 7:
        verdict = "LIKELY PHISHING"
    elif score >= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SAFE"

    iocs = {
        "sender_addresses": sorted({a for a in [from_addr, reply_addr, return_addr] if a}),
        "sender_domains": sorted({d for d in [from_dom, reply_dom, return_dom] if d}),
        "urls_defanged": sorted(defang(u) for u in urls),
        "attachments": [a["filename"] for a in attachments],
    }

    return {
        "subject": subject,
        "from": msg["From"],
        "auth_results": auth,
        "score": score,
        "verdict": verdict,
        "findings": [{"weight": p, "reason": r} for p, r in
                     sorted(findings, reverse=True)],
        "iocs": iocs,
    }


def print_report(r, source):
    print("=" * 70)
    print("  PHISHING E-MAIL TRIAGE REPORT")
    print("  MITRE ATT&CK: T1566 (Phishing)")
    print("=" * 70)
    print(f"  File     : {source}")
    print(f"  From     : {r['from']}")
    print(f"  Subject  : {r['subject']}")
    a = r["auth_results"]
    print(f"  Auth     : spf={a['spf']}  dkim={a['dkim']}  dmarc={a['dmarc']}")
    print("-" * 70)
    print(f"  VERDICT  : {r['verdict']}   (risk score: {r['score']})")
    print("-" * 70)
    if r["findings"]:
        print("  Indicators:")
        for f in r["findings"]:
            print(f"    [+{f['weight']}] {f['reason']}")
    else:
        print("  No phishing indicators found.")
    print("-" * 70)
    print("  IOCs extracted (ready for enrichment):")
    for dom in r["iocs"]["sender_domains"]:
        print(f"    domain : {defang(dom)}")
    for url in r["iocs"]["urls_defanged"]:
        print(f"    url    : {url}")
    for att in r["iocs"]["attachments"]:
        print(f"    file   : {att}")
    print("=" * 70)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Triage a suspicious .eml file for phishing indicators."
    )
    parser.add_argument("emlfile", help="Path to the .eml file to analyse")
    parser.add_argument("--json", metavar="FILE", help="Also write findings to JSON")
    args = parser.parse_args(argv)

    try:
        with open(args.emlfile, "rb") as fh:
            msg = BytesParser(policy=policy.default).parse(fh)
    except FileNotFoundError:
        print(f"error: file not found: {args.emlfile}", file=sys.stderr)
        return 2

    report = analyze(msg)
    print_report(report, args.emlfile)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"  JSON report written to {args.json}")

    return 1 if report["verdict"] != "LIKELY SAFE" else 0


if __name__ == "__main__":
    sys.exit(main())
