# Phishing E-mail Analyzer

A small SOC tool that triages a suspicious e-mail (`.eml`) the way a Tier-1
analyst would: it checks authentication results, hunts for sender spoofing,
extracts and defangs URLs and attachments, scans for social-engineering
language, and prints a weighted verdict with the reasons behind it.

It also outputs the indicators of compromise (IOCs) it found — defanged and
ready to drop into an IOC-enrichment lookup.

**MITRE ATT&CK:** [T1566 – Phishing](https://attack.mitre.org/techniques/T1566/)

## What it checks

- **Authentication** — SPF, DKIM and DMARC results from the headers.
- **Sender spoofing** — `From` vs `Return-Path` vs `Reply-To` domain mismatches,
  and display-name impersonation (e.g. a name claiming "PayPal" sent from an
  unrelated domain).
- **URLs** — links to raw IP addresses, URL shorteners, and the classic tell
  where the *displayed* link doesn't match its real destination.
- **Attachments** — flags risky file types (`.html`, `.exe`, `.zip`, `.js`, …).
- **Social engineering** — urgency and fear language in the subject and body.

Each indicator carries a weight; the total maps to a verdict:

| Verdict           | Score |
|-------------------|-------|
| `LIKELY PHISHING` | ≥ 7   |
| `SUSPICIOUS`      | 3–6   |
| `LIKELY SAFE`     | < 3   |

## Usage

```bash
# Analyse the included phishing sample
python phishing_analyzer.py sample_phishing.eml

# A legitimate e-mail for comparison
python phishing_analyzer.py legitimate.eml

# Export findings + IOCs as JSON
python phishing_analyzer.py sample_phishing.eml --json report.json
```

No external dependencies — just Python 3.8+. Exits non-zero when an e-mail is
not rated safe, so it fits into automated triage pipelines.

## Example output

```
======================================================================
  PHISHING E-MAIL TRIAGE REPORT
  MITRE ATT&CK: T1566 (Phishing)
======================================================================
  From     : PayPal Service <service@paypa1-secure.com>
  Subject  : Urgent: Your account has been limited - verify your account now
  Auth     : spf=fail  dkim=fail  dmarc=fail
----------------------------------------------------------------------
  VERDICT  : LIKELY PHISHING   (risk score: 26)
----------------------------------------------------------------------
  Indicators:
    [+3] Display name mentions "paypal" but the domain is paypa1-secure.com
    [+3] Displayed link (www.paypal.com) does not match destination (203.0.113.99)
    [+3] Link points to a raw IP address: hxxp://203[.]0[.]113[.]99/paypal/login[.]php
    [+3] DMARC failed - message not authorised for the From domain
    ...
  IOCs extracted (ready for enrichment):
    domain : paypa1-secure[.]com
    url    : hxxp://203[.]0[.]113[.]99/paypal/login[.]php
======================================================================
```

The two included samples — one phishing, one a real GitHub notification — let
the tool demonstrate that it separates malicious mail from the legitimate kind
(the GitHub e-mail scores 0).

## How this fits together

This is the triage front-end of a small blue-team toolkit:

1. **Phishing analyzer** (this repo) — pulls IOCs out of a suspicious e-mail.
2. **IOC enrichment** — looks those domains / IPs / URLs up against threat intel.
3. **Brute-force detector** — spots the follow-on activity in the auth logs.

## Limitations & possible next steps

- Authentication verdicts are read from the `Authentication-Results` header
  (i.e. trusts the receiving mail server's checks) rather than re-validating.
- Attachment analysis is by extension, not by content / hash sandboxing.
- A natural extension is auto-hashing attachments and feeding every IOC
  straight into the enrichment tool above.
