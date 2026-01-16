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
  - **NEW**: Transparent scoring justification showing why you got your score
- **MTA-STS Analysis**: Validates Mail Transfer Agent Strict Transport Security DNS records and policy files
- **TLS-RPT Analysis**: Checks SMTP TLS Reporting configuration
- **BIMI Analysis**: Validates Brand Indicators for Message Identification including VMC certificate verification
- **Security Scoring**: Provides an overall security score (0-100) with letter grade (A+ to F)
- **Actionable Recommendations**: Suggests improvements for email security posture
  - Categorized by priority level (Critical, High, Medium, Low)
  - Clear visual hierarchy with counters
- **HTML Report Export**: Generate professional HTML reports
  - **NEW**: Timestamped report files
  - **NEW**: Customizable via YAML configuration (logo, colors, footer)
  - **NEW**: Modern responsive design

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Setup

1. Download latest release (recommended) or clone/download this project
2. Install dependencies:
pip install -r requirements.txt
### Dependencies
dnspython
requests
cryptography
jinja2
pyyaml
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
### With Custom DNS Nameserver
python mailsecwatcher.py -d example.com -ns 8.8.8.8
You can specify a custom DNS nameserver for all queries. Useful for testing, corporate DNS, or troubleshooting.

### Command Line Options

| Option | Description |
|--------|-------------|
| `-d`, `--domain` | Domain name to analyze (required) |
| `-v`, `--verbose` | Enable verbose output with detailed information |
| `-s`, `--selector` | Prompt for custom DKIM selector(s) |
| `-ns`, `--nameserver` | Custom DNS nameserver to use (e.g., 8.8.8.8) |
| `-o`, `--output` | Output format: `html` generates timestamped report file |

### Using Custom DNS Nameserver

Specify a custom DNS nameserver for all DNS queries:

```bash
python mailsecwatcher.py -d example.com -ns 8.8.8.8
```

**Common public DNS servers:**
- **Google DNS**: 8.8.8.8, 8.8.4.4
- **Cloudflare DNS**: 1.1.1.1, 1.0.0.1
- **Quad9**: 9.9.9.9
- **OpenDNS**: 208.67.222.222, 208.67.220.220

**Use cases:**
- Test against specific DNS servers
- Use corporate/internal DNS infrastructure
- Verify DNS propagation across different servers
- DNS troubleshooting and debugging
- Support air-gapped networks

### HTML Report Generation

Generate a professional HTML report with timestamped filename:

```bash
python mailsecwatcher.py -d example.com -o html
```

This creates a file like `output/example.com_20260116_143022.html`.

**Customization**: Edit `config/report_config.yaml` to customize:
- **Branding**: Logo URL, company name, footer text
- **Colors**: Primary, secondary, accent, background, danger colors
- **Output**: Directory and filename format

Example configuration:
```yaml
branding:
  logo_url: "https://example.com/logo.png"
  company_name: "My Company"
  footer_text: "Security Report"

colors:
  primary: "#1d3557"
  secondary: "#457b9d"
  accent: "#a8dadc"
  background: "#f1faee"
  danger: "#e63946"

output:
  directory: "output"
  filename_format: "{domain}_{date}_{time}.html"
```

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
selector1, selector2, google, k1, k2, ctct1, ctct2, sm, s1, s2, sig1, litesrv, zendesk1, zendesk2, mail, email, dkim, default, protonmail, protonmail2, protonmail3, and many more.

**Scoring Logic:**
- **1 selector**: 12 points (basic configuration - add more for redundancy)
- **2+ selectors**: 21 points (maximum score - excellent redundancy)

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
```bash
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

🔑 DKIM (21/21)
   Found 2 selector(s):
   ✅ google
   ✅ selector1
   Scoring: 2 selectors = 21pts (maximum - excellent redundancy)

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

📋 RECOMMENDATIONS:

🟠 HIGH PRIORITY (1)
  • Consider upgrading DMARC policy from 'quarantine' to 'reject'

🟡 MEDIUM PRIORITY (2)
  • Consider strict DKIM alignment (adkim=s) for enhanced security
  • Consider strict SPF alignment (aspf=s) for enhanced security

🟢 LOW PRIORITY (1)
  • Consider implementing BIMI for brand visibility

============================================================
```
## Todo List

- [x] HTML report export
- [ ] PDF/Word report export
- [ ] JSON output format
- [ ] Historical tracking / comparison
- [ ] Bulk domain analysis


## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for details.

## Author

**Enzo LE NAIR**

## Version

**Current**: v2.0.5

## What's New in v2.0.5

### 📄 HTML Report Export
- **New `-o html` option** generates professional timestamped reports
- **Jinja2 templating** for clean separation of code and presentation
- **YAML configuration** (`config/report_config.yaml`) for full customization:
  - Custom logo (URL or path)
  - Company name and footer text
  - Complete color palette
  - Output directory and filename format
- **Modern responsive design** with CSS variables
- **Print-friendly** layout

### Previous Changes (v2.0.4)

#### 🎯 DKIM Scoring Simplified
- **2+ selectors now achieve maximum score** (21/21 points)
- Recognizes that 2 selectors provide sufficient redundancy for production
- Updated scoring justification messages

### v2.0.3

#### 🌐 Custom DNS Nameserver Support
- New `-ns/--nameserver` option to specify custom DNS server
- Useful for testing, corporate DNS, troubleshooting
- IP validation included
- Display message showing which nameserver is in use

#### v2.0.2 Changes

##### 🎯 Categorized Recommendations
- Recommendations now organized by priority: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low
- Clear counters showing number of items per category
- Visual hierarchy for easy scanning
- No more redundant messages between protocol sections and recommendations

##### 📊 DKIM Score Transparency
- Displays scoring justification for each selector count
- Users understand exactly why they received their score
- Clear guidance on how to improve (add more selectors for redundancy)
