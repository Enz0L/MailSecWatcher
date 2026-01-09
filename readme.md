# MailSecWatcher

Personal project: A Python tool to analyze email security mechanisms (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI) for any domain.

## Overview

This tool helps security professionals and domain administrators audit their email authentication infrastructure by querying DNS records and providing a comprehensive security assessment.

## Features

- **SPF Analysis**: Retrieves and evaluates Sender Policy Framework records with full RFC 7208 compliance
  - Recursive redirect resolution
  - DNS lookup counting (10 lookup limit)
  - Security issue detection (+all, ?all, deprecated ptr)
- **DMARC Analysis**: Checks Domain-based Message Authentication, Reporting & Conformance policies
- **DKIM Analysis**: Discovers DKIM selectors and validates their configuration (supports custom selectors)
- **MTA-STS Analysis**: Validates Mail Transfer Agent Strict Transport Security DNS records and policy files
- **TLS-RPT Analysis**: Checks SMTP TLS Reporting configuration
- **BIMI Analysis**: Validates Brand Indicators for Message Identification including VMC certificate verification
- **Security Scoring**: Provides an overall security score (0-100) with letter grade (A+ to F)
- **Actionable Recommendations**: Suggests improvements for email security posture

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Setup

1. Clone or download this project
2. Install dependencies:
pip install -r requirements.txt
### Dependencies
dnspython
requests
cryptography
## Usage

### Basic Analysis
python mailsecwatcher.py -d example.com
### Verbose Mode
python mailsecwatcher.py -d example.com -v
Verbose mode displays additional details:
- SPF DNS lookup breakdown
- Full DKIM records
- Detailed security recommendations

### With Custom DKIM Selector
python mailsecwatcher.py -d example.com -s
When using `-s`, you'll be prompted to enter custom selector(s):
Enter DKIM selector(s) separated by comma: mycompany, mailjet
### Command Line Options

| Option | Description |
|--------|-------------|
| `-d`, `--domain` | Domain name to analyze (required) |
| `-v`, `--verbose` | Enable verbose output with detailed information |
| `-s`, `--selector` | Prompt for custom DKIM selector(s) |

## How It Works

### SPF Resolution

Queries TXT records for `v=spf1` and evaluates the fail mechanism:

| Mechanism | Meaning | Security Level |
|-----------|---------|----------------|
| `-all` | Hardfail | 🟢 Excellent |
| `~all` | Softfail | 🟡 Good |
| `?all` | Neutral | 🟠 Fair |
| `+all` | Pass | 🔴 Critical |

#### SPF Redirect Handling

When an SPF record contains a `redirect=` modifier, the tool:

1. Follows the redirect chain (up to 10 levels)
2. Resolves the final SPF record
3. Displays both the original and redirected SPF records
4. Detects redirect loops and broken redirects
5. Accumulates DNS lookups across the entire chain

#### DNS Lookup Limit

RFC 7208 limits SPF to 10 DNS lookups. The tool counts lookups from:
- `include:` mechanisms
- `a` and `mx` mechanisms
- `ptr` mechanism (deprecated)
- `exists:` mechanism
- `redirect=` modifier

#### Security Checks

The tool detects:
- **CRITICAL**: `+all` allows any server to spoof the domain
- **WARNING**: `?all` provides no protection
- **WARNING**: `ptr` mechanism is deprecated (RFC 7208 Section 5.5)

### DMARC Resolution

Queries `_dmarc.{domain}` TXT record and validates:

| Tag | Description | Default Value |
|-----|-------------|---------------|
| `p` | Policy for domain | (required) |
| `sp` | Subdomain policy | Inherits from `p` |
| `adkim` | DKIM alignment | `r` (relaxed) |
| `aspf` | SPF alignment | `r` (relaxed) |
| `pct` | Percentage to apply policy | `100` |
| `rua` | Aggregate report URI | (none) |
| `ruf` | Forensic report URI | (none) |
| `fo` | Failure reporting options | `0` |
| `ri` | Report interval (seconds) | `86400` |

### DKIM Resolution

Tests common selectors against `{selector}._domainkey.{domain}`:

**Built-in selectors tested:**
selector1, selector2, google, k1, k2, ctct1, ctct2, sm, s1, s2, sig1, litesrv, zendesk1, zendesk2, mail, email, dkim, default, and many more.

### MTA-STS Resolution

1. Queries `_mta-sts.{domain}` TXT record for `v=STSv1`
2. Fetches policy from `https://mta-sts.{domain}/.well-known/mta-sts.txt`
3. Validates mode (enforce/testing/none)

### TLS-RPT Resolution

Queries `_smtp._tls.{domain}` TXT record for `v=TLSRPTv1` and extracts reporting URI.

### BIMI Resolution

Queries `default._bimi.{domain}` TXT record and validates:
- **DMARC Compliance**: Requires `p=quarantine` or `p=reject`
- **Logo URL**: Must be HTTPS and SVG format
- **VMC Certificate** (if present):
  - Authorized CAs (DigiCert, Entrust, GlobalSign, SSL.com, Sectigo, Comodo)
  - Domain Match via SAN extension
  - BIMI EKU OID 1.3.6.1.5.5.7.3.31
  ## Scoring System

| Component | Max Points |
|-----------|------------|
| SPF | 20 |
| DMARC | 27 |
| DKIM | 21 |
| MTA-STS | 12 |
| TLS-RPT | 12 |
| BIMI | 8 |
| **Total** | **100** |

### SPF Scoring Details

| Condition | Points |
|-----------|--------|
| Base (record exists) | 5 |
| Hardfail (-all) | +12 |
| Softfail (~all) | +7 |
| Neutral (?all) | +2 |
| Has mechanisms | +3 |
| Null SPF (v=spf1 -all) | 20 |
| Critical issue (+all) | 0 |
| Broken redirect | 3 |

### Grades

| Score | Grade |
|-------|-------|
| 90-100 | A+ 🟢 |
| 80-89 | A 🟢 |
| 70-79 | B 🟡 |
| 60-69 | C 🟡 |
| 50-59 | D 🟠 |
| 40-49 | E 🟠 |
| 0-39 | F 🔴 |

## Example Output
🔍 Analyzing domain: example.com
   Please wait...

============================================================
  EMAIL SECURITY ANALYSIS: example.com
============================================================

🟢 OVERALL SCORE: 85/100 (Grade: A)

──────────────────────────────────────────────────────────────

📧 SPF (17/20)
   Record: v=spf1 redirect=_spf.example.net
   ↪️  Redirect: _spf.example.net
   ✅ Redirected SPF: v=spf1 include:_spf.google.com -all
   Effective mechanism: hardfail
   DNS Lookups: ✅ 4/10

📧 DMARC (22/27)
   Record: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com
   Policy: quarantine
   Subdomain Policy: quarantine (inherited)
   DKIM Alignment: relaxed (default)
   SPF Alignment: relaxed (default)
   Percentage: 100%
   Reporting: ✅ rua configured

📧 DKIM (17/21)
   ✅ google: v=DKIM1; k=rsa; p=MIIBIjAN...
   ✅ selector1: v=DKIM1; k=rsa; p=MIGfMA0G...

🔒 MTA-STS (12/12)
   Record: v=STSv1; id=20240115
   Policy: ✅ Accessible

📊 TLS-RPT (12/12)
   Record: v=TLSRPTv1; rua=mailto:tlsrpt@example.com
   Reporting URI: mailto:tlsrpt@example.com

🎨 BIMI (5/8)
   Record: v=BIMI1; l=https://example.com/logo.svg
   DMARC Compliant: ✅ Yes
   Logo: ✅ Accessible (SVG, HTTPS)

──────────────────────────────────────────────────────────────

📊 SCORE BREAKDOWN:
   SPF:     17/20  █████████████████░░░
   DMARC:   22/27  ████████████████░░░░
   DKIM:    17/21  ████████████████░░░░
   MTA-STS: 12/12  ████████████████████
   TLS-RPT: 12/12  ████████████████████
   BIMI:     5/8   ████████████░░░░░░░░

💡 RECOMMENDED ACTIONS:
• Upgrade DMARC policy from p=quarantine to p=reject
• Consider adding VMC certificate for enhanced BIMI support

============================================================
## Todo List

- [ ] HTML report export
- [ ] PDF/Word report export
- [ ] JSON output format
- [ ] Historical tracking / comparison
- [ ] API mode
- [ ] Recursive include: resolution
- [ ] DANE/TLSA support
- [ ] Bulk domain analysis

## Changelog

### V1.5.0 (Current)

#### New Features
- Full SPF redirect support with chain resolution
- DNS lookup counting per RFC 7208
- SPF security analysis (detects +all, ?all, ptr)
- Verbose mode (-v flag)
- Null SPF detection (v=spf1 -all)

#### Improvements
- Better redirect display showing original and final SPF
- Intermediate redirects tracked and displayed
- Loop detection in redirect chains
- Total DNS lookups across redirect chain analyzed

#### Scoring Changes
- SPF max score: 18 → 20
- MTA-STS max score: 14 → 12
- TLS-RPT max score: 10 → 12
- New penalty for broken redirects (score: 3)
- Null SPF (v=spf1 -all) now scores 20/20

### V1.4.5 (Previous)
- Initial BIMI VMC verification
- MTA-STS policy fetching
- TLS-RPT support

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for details.

## Author

**Enzo LE NAIR**

## Version

V1.4.5