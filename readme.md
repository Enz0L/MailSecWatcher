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

# Todo list

- MTA-STS

- TLS-RPT

- HTML report

- WORD report

- Tracking file