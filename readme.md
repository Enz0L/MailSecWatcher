# MailSecWatcher

Personal project: A Python tool to analyze email  mechanisms (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI) for any domain.

## Overview

This tool helps security professionals and domain administrators audit their email authentication infrastructure by querying DNS records and providing a comprehensive security assessment.

## Features

- **SPF Analysis**: Retrieves and evaluates Sender Policy Framework records
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

```bash
pip install -r requirements.txt
```

### Dependencies

```
dnspython
requests
cryptography
```

## Usage

### Basic Analysis

```bash
python mailsecwatcher.py -d example.com
```

### With Custom DKIM Selector

```bash
python mailsecwatcher.py -d example.com -s
```

When using `-s`, you'll be prompted to enter custom selector(s):

```
🔑 DKIM Custom Selector Mode
------------------------------
Enter selector(s) to test (comma-separated for multiple)
Example: myselector1, myselector2
Selector(s): mycompany, mailjet
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-d`, `--domain` | Domain name to analyze (required) |
| `-s`, `--selector` | Prompt for custom DKIM selector(s) |

## How It Works

### SPF Resolution

Queries TXT records for `v=spf1` and evaluates the fail mechanism:

| Mechanism | Meaning | Security Level |
|-----------|---------|----------------|
| `-all` | Hardfail | 🟢 Excellent |
| `~all` | Softfail | 🟡 Good |
| `?all` | Neutral | 🟠 Fair |
| `+all` | Pass | 🔴 Poor |

### DMARC Resolution

Queries `_dmarc.{domain}` TXT record and validates:

- `p=` policy (none/quarantine/reject)
- `sp=` subdomain policy
- `rua=` aggregate reports
- `ruf=` forensic reports
- `adkim=` DKIM alignment (strict/relaxed)
- `aspf=` SPF alignment (strict/relaxed)

### DKIM Resolution

Scans 50+ common selectors including:

```
selector1, selector2, google, k1, k2, mandrill, zendesk1, zendesk2,
protonmail, protonmail2, protonmail3, default, dkim, mail, s1, s2...
```

Supports both CNAME and TXT record types.

### MTA-STS Resolution

- Queries `_mta-sts.{domain}` TXT record for `v=STSv1`
- Fetches policy file from `https://mta-sts.{domain}/.well-known/mta-sts.txt`
- Validates:
  - `mode:` (enforce/testing/none)
  - `mx:` authorized mail servers
  - `max_age:` policy cache duration

### TLS-RPT Resolution

Queries `_smtp._tls.{domain}` TXT record and validates:

- `v=TLSRPTv1` version tag
- `rua=` reporting URI (mailto: or https:)

### BIMI Resolution

Queries `default._bimi.{domain}` TXT record and validates:

- `v=BIMI1` version tag
- `l=` logo URL (SVG format required)
- `a=` VMC (Verified Mark Certificate) URL

#### VMC Certificate Verification

When a VMC URL is present, the tool performs comprehensive validation:

- **Validity**: Certificate expiration and activation dates
- **Issuer**: Verification against authorized CAs (DigiCert, Entrust, GlobalSign, SSL.com, Sectigo, Comodo)
- **Domain Match**: Certificate CN/SAN matches target domain
- **BIMI EKU**: Extended Key Usage OID 1.3.6.1.5.5.7.3.31
- **Embedded Logo**: Logotype extension presence (OID 1.3.6.1.5.5.7.1.12)

## Scoring System

| Component | Max Points |
|-----------|------------|
| SPF | 18 |
| DMARC | 27 |
| DKIM | 21 |
| MTA-STS | 14 |
| TLS-RPT | 10 |
| BIMI | 8 |
| **Total** | **100** |

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

```
Analyzing domain: example.com

============================================================
  EMAIL SECURITY ANALYSIS: example.com
============================================================

📧 SPF (15/18)
   Record: "v=spf1 include:_spf.google.com ~all"
   Mechanism: softfail

📧 DMARC (22/27)
   Record: "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"

📧 DKIM (14/21)
   ✅ Selector: google (CNAME)
   ✅ Selector: selector1 (TXT)

🔒 MTA-STS (14/14)
   DNS: "v=STSv1; id=20240115"
   Mode: enforce
   MX: mail.example.com

📊 TLS-RPT (10/10)
   Record: "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
   Report URI: mailto:tlsrpt@example.com

🎨 BIMI (5/8)
   Record: "v=BIMI1; l=https://example.com/logo.svg"
   DMARC Compliant: ✅ Yes
   Logo: ✅ https://example.com/logo.svg

============================================================
  TOTAL SCORE: 80/100 - Grade: 🟢 A
============================================================

📊 Score Breakdown:
   SPF:     15/18  ██████████░░
   DMARC:   22/27  █████████░░░
   DKIM:    14/21  ████████░░░░
   MTA-STS: 14/14  ████████████
   TLS-RPT: 10/10  ████████████
   BIMI:     5/8   ███████░░░░░

💡 Recommendations:
  • Use '-all' (hardfail) instead of '~all' in SPF
  • Consider adding VMC certificate for enhanced BIMI support
```

## Todo List

- [ ] HTML report export
- [ ] PDF/Word report export
- [ ] JSON output format
- [ ] Historical tracking / comparison
- [ ] API mode


## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for details.

## Author

**Enzo LE NAIR**

## Version

V1.3.3
