# Release Notes - MailSecWatcher v2.0.5

## 📄 New Feature: HTML Report Generation

### Summary

Added ability to generate beautiful, customizable HTML reports using the `-o html` option. Reports are generated with timestamped filenames and support full branding customization via YAML configuration.

### Usage

```bash
python mailsecw.py -d example.com -o html
```

This generates a file like `output/example.com_20260116_143052.html`

### Features

**Jinja2 Templating**
- Modern, responsive HTML template
- Clean design with professional styling
- Print-friendly layout

**YAML Configuration** (`config/report_config.yaml`)
- Customizable logo (URL or local path)
- Company name and footer text
- Full color palette customization
- Output directory and filename format

**Design Highlights**
- Modern 2026 design aesthetic
- Gradient headers and subtle shadows
- Protocol cards with hover effects
- Color-coded recommendations by priority
- Responsive layout for all screen sizes

### Configuration Example

```yaml
branding:
  logo_url: "https://example.com/logo.png"
  company_name: "My Company"
  footer_text: "Security Report by My Company"

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

### New Files

- `templates/report.html` - Jinja2 HTML template
- `config/report_config.yaml` - User configuration file
- `output/` - Directory for generated reports (auto-created)

### Code Changes

**New Dependencies**
- `jinja2` - Template engine
- `pyyaml` - YAML configuration parsing

**mailsecw.py Modifications**
- Added `-o/--output` CLI argument (choices: html)
- Added `load_report_config()` function
- Added `generate_html_report()` function
- Modified `main()` to call report generation when requested

### Benefits

✅ **Professional reports** - Share results with stakeholders
✅ **Full customization** - Brand reports with your logo and colors
✅ **No external dependencies** - Self-contained HTML files
✅ **Print-ready** - Optimized for PDF export via browser print

---

**Release Date**: 2026-01-16
**Version**: v2.0.5
**Type**: New Feature

---

---

# Release Notes - MailSecWatcher v2.0.4

## 🎯 Update: DKIM Scoring Simplified

### Summary

Modified DKIM scoring to award maximum points (21/21) when 2 or more selectors are found, recognizing that 2 selectors provide sufficient redundancy for production use.

### Changes

**Scoring Logic Updated**
- **Previous**: 1 selector = 12pts, 2 selectors = 17pts, 3+ selectors = 21pts
- **New**: 1 selector = 12pts, **2+ selectors = 21pts (maximum)**

**Code Modifications**
- Updated `calculate_dkim_score()` function (mailsecw.py line 723-735)
- Updated scoring justification display (mailsecw.py line 1351-1354)
- Updated README.md documentation

### Rationale

- **Industry alignment**: 2 DKIM selectors are considered best practice for redundancy
- **Simplified logic**: Clear threshold at 2 selectors
- **Realistic expectations**: Most well-configured domains use 2 selectors
- **Better user experience**: Domains with 2 selectors receive full credit

### Example Output

#### Before
```
🔑 DKIM (17/21)
   Found 2 selector(s):
   ✅ protonmail
   ✅ protonmail2
   Scoring: 2 selectors = 17pts (3+ selectors = 21pts)
```

#### After
```
🔑 DKIM (21/21)
   Found 2 selector(s):
   ✅ protonmail
   ✅ protonmail2
   Scoring: 2 selectors = 21pts (maximum - excellent redundancy)
```

### Impact

- Domains with 2 DKIM selectors now receive full DKIM score (+4 points)
- Overall security scores increase by up to 4 points
- Encourages adoption of multi-selector DKIM configuration

### Benefits

✅ **Realistic scoring** - Aligns with industry best practices
✅ **Simplified logic** - Clear 2-selector threshold
✅ **Better UX** - Users with 2 selectors get maximum recognition
✅ **Encourages redundancy** - Still emphasizes multiple selectors over single

---

**Release Date**: 2026-01-14
**Version**: v2.0.4
**Type**: Enhancement

---

---

# Release Notes - MailSecWatcher v2.0.3

## 🌐 New Feature: Custom DNS Nameserver Support

### Summary

Added ability to specify a custom DNS nameserver for all queries using the `-ns` flag.

### Usage

```bash
python mailsecw.py -d example.com -ns 8.8.8.8
```

### Changes

**CLI Argument Added (line 80-83)**
- New `-ns/--nameserver` option
- Accepts IP address as parameter
- Includes IP validation with error handling

**Global DNS Resolver (line 31-32)**
- Added `DNS_RESOLVER` global variable
- Defaults to `dns.resolver` (system DNS)
- Can be customized via `-ns` option

**Main Function Configuration (lines 1484-1494)**
- Validates IP address format using `ipaddress` module
- Creates custom `Resolver()` instance if nameserver specified
- Displays nameserver in use: "🌐 Using nameserver: X.X.X.X"
- Exits with error if invalid IP provided

**DNS Functions Updated (7 functions modified)**
- `resolve_spf_redirect()` - line 224
- `spf_resolver()` - line 453
- `dmarc_resolver()` - line 631
- `dkim_resolver()` - line 708
- `mta_sts_resolver()` - line 755
- `tlsrpt_resolver()` - line 823
- `bimi_resolver()` - line 1018

All now use `DNS_RESOLVER.resolve()` instead of `dns.resolver.resolve()`

### Example Output

```bash
$ python mailsecw.py -d google.com -ns 8.8.8.8
🌐 Using nameserver: 8.8.8.8

🔍 Analyzing domain: google.com
   Please wait...
```

### Use Cases

- **Testing**: Verify DNS propagation across different servers
- **Corporate DNS**: Use internal DNS infrastructure
- **Troubleshooting**: Isolate DNS-related issues
- **Air-gapped networks**: Support isolated environments
- **DNS comparison**: Compare results from different DNS providers

### Common Public DNS Servers

- **Google DNS**: 8.8.8.8, 8.8.4.4
- **Cloudflare DNS**: 1.1.1.1, 1.0.0.1
- **Quad9**: 9.9.9.9
- **OpenDNS**: 208.67.222.222, 208.67.220.220

### Benefits

✅ **Flexibility** - Choose any DNS server
✅ **Testing** - Verify DNS propagation
✅ **Corporate** - Use internal DNS
✅ **Debugging** - Isolate DNS issues
✅ **Validation** - IP format validation included

### Tests Performed

- ✅ Test with Google DNS (8.8.8.8)
- ✅ Test with Cloudflare DNS (1.1.1.1)
- ✅ Test without `-ns` option (default behavior)
- ✅ Test with invalid IP (validation works)
- ✅ All 7 DNS functions verified

---

**Release Date**: 2026-01-12
**Version**: v2.0.3
**Type**: Enhancement

---

---

# Release Notes - MailSecWatcher v2.0.2

## 🎯 New Feature: Categorized Recommendations

### Summary of Changes

This version significantly improves the readability and usefulness of the recommendations section by introducing a 4-level prioritization system.

### Main Improvements

#### 1. **Priority Categorization**

Recommendations are now organized into 4 distinct categories:

- **🔴 CRITICAL ISSUES** - Security vulnerabilities requiring immediate action
  - Missing SPF or SPF with +all (allows complete spoofing)
  - Broken SPF redirect
  - SPF > 10 DNS lookups (RFC non-compliance)
  - Missing DMARC or p=none
  - Missing DKIM
  - Missing DMARC aggregate reporting

- **🟠 HIGH PRIORITY** - Missing or misconfigured essential protections
  - SPF softfail (~all) instead of hardfail (-all)
  - DMARC p=quarantine (should be p=reject)
  - No explicit DMARC subdomain policy
  - Missing DMARC forensic reporting
  - SPF close to DNS limit (8-10 lookups)

- **🟡 MEDIUM PRIORITY** - Configuration optimizations
  - Non-strict DMARC alignments (adkim/aspf)
  - MTA-STS in testing mode

- **🟢 LOW PRIORITY** - Optional advanced features
  - Missing MTA-STS
  - Missing TLS-RPT
  - Missing BIMI or BIMI blocked by DMARC

#### 2. **Counters per Category**

Each priority level now displays the number of recommendations, for example:
```
🔴 CRITICAL ISSUES (2)
🟠 HIGH PRIORITY (3)
```

#### 3. **Clear Visual Hierarchy**

- Consistent emojis for each level
- List item indentation
- Visual separation between categories
- Congratulations message if no recommendations

#### 4. **Elimination of Redundancies**

Recommendations no longer repeat issues already displayed in the protocol sections.

### Technical Changes

#### New Code

**Function `categorize_recommendations()` (line 1102)**
- Analyzes all protocol results
- Applies prioritization logic
- Returns a dictionary with 4 categories

**Display Refactoring (lines 1403-1454)**
- Call to `categorize_recommendations()`
- Structured display by category
- Dynamic counters
- Handling of "no recommendations" case

### User Impact

#### Before
```
📋 RECOMMENDATIONS:
• 🔴 Implement SPF record
• Consider upgrading SPF from ~all to -all
• 🔴 Add DMARC aggregate reporting
• Consider strict DKIM alignment
• Consider implementing MTA-STS
```

#### After
```
📋 RECOMMENDATIONS:

🔴 CRITICAL ISSUES (2)
  • Implement SPF record to prevent email spoofing
  • Add DMARC aggregate reporting (rua=mailto:...)

🟠 HIGH PRIORITY (1)
  • Consider upgrading SPF from ~all (softfail) to -all (hardfail)

🟡 MEDIUM PRIORITY (1)
  • Consider strict DKIM alignment (adkim=s) for enhanced security

🟢 LOW PRIORITY (1)
  • Consider implementing MTA-STS for transport security
```

### Benefits

✅ **Clear Prioritization** - Users know where to start
✅ **Visual Hierarchy** - Quick identification of critical issues
✅ **Dependency Respect** - BIMI placed in LOW as it requires DMARC
✅ **Conciseness** - Short and direct recommendations
✅ **Scalability** - Easily extensible structure

### Tests Performed

- ✅ Unprotected domain (low score) → CRITICAL recommendations only
- ✅ Domain with partial configuration → Mix of HIGH/MEDIUM/LOW
- ✅ Well-configured domain → MEDIUM/LOW or congratulations message
- ✅ Tests with google.com (60/100, grade C)
- ✅ Tests with github.com (57/100, grade D)

### Compatibility

- ✅ No breaking changes
- ✅ Same user interface (CLI arguments unchanged)
- ✅ Same output structure (categories added)
- ✅ Compatible with all Python 3.6+ versions

---

---

## 🎯 Improvement: DKIM Score Justification Display

### Summary

Added transparent scoring justification for DKIM to help users understand why they received their specific score.

### Changes

**DKIM Display Enhancement (line 1343-1349)**
- Added scoring explanation based on number of selectors found
- Shows what score corresponds to selector count
- Provides guidance for improvement (e.g., "consider adding more for redundancy")

### Example Output

#### Before
```
🔑 DKIM (17/21)
   Found 2 selector(s):
   ✅ protonmail
   ✅ protonmail2
```

#### After
```
🔑 DKIM (17/21)
   Found 2 selector(s):
   ✅ protonmail
   ✅ protonmail2
   Scoring: 2 selectors = 17pts (3+ selectors = 21pts)
```

### Scoring Logic Displayed

- **1 selector**: 12pts (with suggestion to add more for redundancy)
- **2 selectors**: 17pts (shows 3+ needed for maximum)
- **3+ selectors**: 21pts (maximum score)

### Benefits

✅ **Transparency** - Users understand how the score is calculated
✅ **Guidance** - Clear indication of how to improve the score
✅ **Context** - Explains why having multiple selectors matters

---

## 📝 Documentation: README Updated

### Summary

Updated README.md to reflect all new features introduced in v2.0.2.

### Changes Made

1. **Features Section**
   - Added "NEW" badges for DKIM score transparency
   - Added "NEW" badges for categorized recommendations (3 bullet points)

2. **DKIM Resolution Section**
   - Added ProtonMail selectors to the built-in list
   - Added "Scoring Logic" subsection explaining the point system

3. **Example Output Section**
   - Updated DKIM display with scoring justification
   - Replaced "SCORE BREAKDOWN" with new "RECOMMENDATIONS" format
   - Shows categorized recommendations with counters

4. **Version Section**
   - Updated version number: v1.4.5 → v2.0.2
   - Added "What's New in v2.0.2" section
   - Added version history for context

### Benefits

✅ **Up-to-date documentation** - Users see what's new at a glance
✅ **Visual examples** - Clear understanding of new output format
✅ **Version tracking** - Easy to see changes between versions

---

**Release Date**: 2026-01-10
**Version**: v2.0.2
**Type**: Enhancement
