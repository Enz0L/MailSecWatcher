# MailSecWatcher
Personal project: A Python tool to analyze email authentication mechanisms (SPF, DMARC, DKIM, TLS-RPT, and MTA-STS) for any domain.

## Overview

This tool helps security professionals and domain administrators audit their email authentication infrastructure by querying DNS records and providing a comprehensive security assessment.

## Features

- **SPF Analysis**: Retrieves and evaluates Sender Policy Framework records
- **DMARC Analysis**: Checks Domain-based Message Authentication, Reporting & Conformance policies
- **DKIM Analysis**: Discovers DKIM selectors and validates their configuration
- **Security Scoring**: Provides an overall security score (0-100) based on implementation
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
# Usage
```bash
python analyzer.py -d example.com
```
# How It Works

## SPF Resolution
Queries TXT records for v=spf1 and evaluates the fail mechanism:
- Mechanism
- Meaning
- Security Level

-all
Hardfail
🟢 Excellent

~all
Softfail
🟡 Good

?all
Neutral
🟠 Fair

+all
Pass
🔴 Poor


# DMARC Resolution
Queries _dmarc.{domain} TXT record and validates:

- p= policy (none/quarantine/reject)
- rua= aggregate reports
- ruf= forensic reports
- pct= enforcement percentage

# DKIM Resolution
Scans 40+ common selectors:
selector1, selector2, google, k1, k2, mandrill, zendesk1, protonmail...

# Todo list

- Add the possibility to use custom selector with argparse.

- MTA-STS

- TLS-RPT

- HTML report

- WORD report

- Tracking file