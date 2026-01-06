# Author: Enzo LE NAIR
# Version: V1.4.0
# Descr: Mail DNS-based protection checker
#   MailSecWatcher - Tool in development
#   Copyright (C) 2025  Enzo LE NAIR
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as
#   published by the Free Software Foundation, either version 3 of the
#   License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

from argparse import ArgumentParser
import dns.resolver
import requests
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from datetime import datetime, timezone

AUTHORIZED_VMC_CA = [
    "DigiCert",
    "Entrust",
    "GlobalSign",
    "SSL.com",
    "Sectigo",
    "Comodo"
]

BIMI_EKU_OID = "1.3.6.1.5.5.7.3.31"

# Common DKIM selectors with provider associations
COMMON_SELECTORS = [
    "default", "dkim", "mail", "email", "selector1", "selector2",
    "google", "k1", "k2", "s1", "s2", "sig1", "smtp", "mx",
    "mailjet", "mandrill", "sendgrid", "amazonses", "postmark"
]

def prog_parse():
    parser = ArgumentParser(
        prog=__file__,
        description="Analyze SPF, DMARC, DKIM, TLS-RPT, MTA-STS & BIMI",
        usage="%(prog)s [options] -d domaine_name"
    )
    parser.add_argument("-d", "--domain", help="Specify domain name", required=True)
    parser.add_argument("-s", "--selector", action="store_true", help="Prompt for custom DKIM selector(s)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    options = parser.parse_args()
    return options


# =============================================================================
# SPF FUNCTIONS
# =============================================================================

def count_spf_dns_lookups(spf_record):
    """
    Count DNS lookups in SPF record (RFC 7208 limit: 10).
    Mechanisms that require DNS lookups: include, a, mx, ptr, exists, redirect
    """
    if not spf_record:
        return 0, []
    
    spf_lower = spf_record.lower()
    lookups = []
    
    # Patterns that require DNS lookups
    lookup_patterns = [
        (r'include:([^\s]+)', 'include'),
        (r'redirect=([^\s]+)', 'redirect'),
        (r'exists:([^\s]+)', 'exists'),
        (r'(?:^v=spf1\s+|\s+)[+\-~?]?a(?:[:\/]([^\s]+))?(?:\s|$)', 'a'),
        (r'(?:^v=spf1\s+|\s+)[+\-~?]?mx(?:[:\/]([^\s]+))?(?:\s|$)', 'mx'),
        (r'(?:^v=spf1\s+|\s+)[+\-~?]?ptr(?::([^\s]+))?(?:\s|$)', 'ptr'),
    ]
    
    for pattern, mech_type in lookup_patterns:
        matches = re.findall(pattern, spf_lower)
        for match in matches:
            lookups.append({
                'type': mech_type,
                'value': match if match else '(domain itself)'
            })
    
    return len(lookups), lookups


def analyze_spf_security(spf_record):
    """
    Analyze SPF record for security issues.
    Returns: (issues, warnings, is_null_spf)
    """
    issues = []
    warnings = []
    is_null_spf = False
    
    if not spf_record:
        return issues, warnings, is_null_spf
    
    spf_lower = spf_record.lower().replace('"', '').strip()
    
    # Check for null SPF (domain sends no mail) - this is valid!
    if spf_lower == "v=spf1 -all":
        is_null_spf = True
        return issues, warnings, is_null_spf
    
    # CRITICAL: +all allows anyone to send
    if "+all" in spf_lower or spf_lower.endswith(" all"):
        issues.append({
            'severity': 'CRITICAL',
            'message': '+all allows ANY server to send email as this domain',
            'recommendation': 'Change to -all (hardfail) or ~all (softfail)'
        })
    
    # WARNING: ?all provides no protection
    if "?all" in spf_lower:
        warnings.append({
            'severity': 'WARNING',
            'message': '?all (neutral) provides no spam protection',
            'recommendation': 'Change to -all (hardfail) or ~all (softfail)'
        })
    
    # WARNING: ptr mechanism is deprecated (RFC 7208)
    if re.search(r'(?:^v=spf1\s+|\s+)[+\-~?]?ptr(?:[:\/\s]|$)', spf_lower):
        warnings.append({
            'severity': 'WARNING',
            'message': 'ptr mechanism is deprecated (RFC 7208 Section 5.5)',
            'recommendation': 'Replace ptr with explicit ip4/ip6 or include mechanisms'
        })
    
    # Check DNS lookup count
    lookup_count, lookups = count_spf_dns_lookups(spf_record)
    if lookup_count > 10:
        issues.append({
            'severity': 'ERROR',
            'message': f'SPF exceeds 10 DNS lookup limit ({lookup_count} lookups)',
            'recommendation': 'Reduce include/redirect mechanisms or flatten SPF record',
            'details': lookups
        })
    elif lookup_count > 7:
        warnings.append({
            'severity': 'WARNING',
            'message': f'SPF has {lookup_count}/10 DNS lookups (approaching limit)',
            'recommendation': 'Consider flattening SPF record to avoid future issues'
        })
    
    return issues, warnings, is_null_spf


def spf_resolver(domain):
    mechanism = {
        "-all": "hardfail",
        "~all": "softfail",
        "?all": "neutral",
        "+all": "pass"
    }
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf = None
        for answer in answers:
            if "v=spf1" in answer.to_text():
                spf = answer.to_text()
                break
        if spf:
            spf_meca = next((meca for pattern, meca in mechanism.items() if pattern in spf), "hardfail")
            
            # Analyze security
            issues, warnings, is_null_spf = analyze_spf_security(spf)
            lookup_count, lookups = count_spf_dns_lookups(spf)
            
            return {
                'record': spf,
                'mechanism': spf_meca,
                'issues': issues,
                'warnings': warnings,
                'is_null_spf': is_null_spf,
                'dns_lookups': lookup_count,
                'lookup_details': lookups
            }
        return None
    except Exception:
        return None


def has_spf_mechanisms(spf_record):
    """Check if SPF record contains valid mechanisms indicating proper configuration."""
    if not spf_record:
        return False
    
    spf_lower = spf_record.lower()
    
    # Direct match mechanisms
    direct_mechanisms = ["include:", "ip4:", "ip6:", "redirect=", "exists:", "ptr"]
    if any(m in spf_lower for m in direct_mechanisms):
        return True
    
    # Regex patterns for 'a' and 'mx' mechanisms
    a_pattern = r'(?:^v=spf1\s+|\s+)[+\-~?]?a(?:[:\/\s]|$)'
    mx_pattern = r'(?:^v=spf1\s+|\s+)[+\-~?]?mx(?:[:\/\s]|$)'
    
    if re.search(a_pattern, spf_lower):
        return True
    if re.search(mx_pattern, spf_lower):
        return True
    
    return False


def calculate_spf_score(spf_result):
    """Calculate SPF score with security checks."""
    if not spf_result:
        return 0
    
    # Handle dict format (new) or tuple format (legacy)
    if isinstance(spf_result, dict):
        spf_record = spf_result.get('record')
        spf_mechanism = spf_result.get('mechanism')
        issues = spf_result.get('issues', [])
        is_null_spf = spf_result.get('is_null_spf', False)
    else:
        # Legacy tuple format
        spf_record, spf_mechanism = spf_result
        issues = []
        is_null_spf = False
    
    if not spf_record:
        return 0
    
    # CRITICAL issues = 0 score
    critical_issues = [i for i in issues if i.get('severity') == 'CRITICAL']
    if critical_issues:
        return 0
    
    # Null SPF (v=spf1 -all) = perfect for non-sending domain
    if is_null_spf:
        return 20
    
    # DNS lookup exceeded = major penalty
    error_issues = [i for i in issues if i.get('severity') == 'ERROR']
    if error_issues:
        return 5  # Only base points
    
    score = 5  # Record exists
    
    if spf_mechanism == "hardfail":
        score += 12
    elif spf_mechanism == "softfail":
        score += 7
    elif spf_mechanism == "neutral":
        score += 3
    elif spf_mechanism == "pass":
        score += 0
    
    if has_spf_mechanisms(spf_record):
        score += 3
    
    return min(score, 20)


# =============================================================================
# DMARC FUNCTIONS
# =============================================================================

def dmarc_resolver(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for answer in answers:
            if "v=DMARC1" in answer.to_text():
                dmarc = answer.to_text()
                return dmarc
        return None
    except Exception:
        return None


def parse_dmarc_tags(dmarc_record):
    """Parse DMARC record and return tags with effective values (including defaults)."""
    if not dmarc_record:
        return {}
    
    # RFC 7489 default values
    defaults = {
        "p": None,        # Required, no default
        "sp": None,       # Defaults to p= value
        "adkim": "r",     # Relaxed
        "aspf": "r",      # Relaxed
        "pct": "100",
        "fo": "0",
        "ri": "86400",
        "rf": "afrf"
    }
    
    tags = {}
    parts = dmarc_record.replace('"', '').split(';')
    
    for part in parts:
        part = part.strip()
        if '=' in part:
            key, value = part.split('=', 1)
            tags[key.strip().lower()] = value.strip()
    
    # Apply defaults for missing tags
    result = {
        "explicit": tags.copy(),
        "effective": {}
    }
    
    # Set effective values
    for key, default in defaults.items():
        if key in tags:
            result["effective"][key] = tags[key]
        elif key == "sp" and "p" in tags:
            # sp defaults to p value
            result["effective"]["sp"] = tags["p"]
        elif default is not None:
            result["effective"][key] = default
    
    # Copy p if present
    if "p" in tags:
        result["effective"]["p"] = tags["p"]
    
    # Extract rua and ruf
    if "rua" in tags:
        result["effective"]["rua"] = tags["rua"]
    if "ruf" in tags:
        result["effective"]["ruf"] = tags["ruf"]
    
    return result


def calculate_dmarc_score(dmarc_result):
    if not dmarc_result:
        return 0
    
    parsed = parse_dmarc_tags(dmarc_result)
    effective = parsed.get("effective", {})
    explicit = parsed.get("explicit", {})
    
    score = 5  # Record exists
    
    # Policy scoring
    policy = effective.get("p", "").lower()
    if policy == "reject":
        score += 10
    elif policy == "quarantine":
        score += 7
    elif policy == "none":
        score += 1  # Reduced from 3 - monitoring only, no protection
    
    # Reporting
    if "rua" in explicit:
        score += 5
    if "ruf" in explicit:
        score += 3
    
    # Explicit subdomain policy
    if "sp" in explicit:
        score += 2
    
    # pct=100
    if effective.get("pct") == "100":
        score += 2
    
    return min(score, 27)


def check_dmarc_compliance(dmarc_record):
    if not dmarc_record:
        return False
    dmarc_lower = dmarc_record.lower()
    if "p=reject" in dmarc_lower or "p=quarantine" in dmarc_lower:
        return True
    return False


# =============================================================================
# DKIM FUNCTIONS
# =============================================================================

def get_smart_selectors(domain, mx_records=None):
    """Generate smart DKIM selectors based on domain and MX records."""
    selectors = set(COMMON_SELECTORS)
    
    # Domain-based selectors
    domain_parts = domain.split('.')
    if domain_parts:
        selectors.add(domain_parts[0])
        selectors.add(domain.replace('.', ''))
    
    # Date-based selectors
    current_year = datetime.now().year
    selectors.add(f"s{current_year}")
    selectors.add(f"selector{current_year}")
    selectors.add(f"dkim{current_year}")
    
    # MX-based selectors
    if mx_records:
        for mx in mx_records:
            mx_lower = mx.lower()
            if "google" in mx_lower or "gmail" in mx_lower:
                selectors.add("google")
                selectors.add("20161025")
                selectors.add("20230601")
            elif "outlook" in mx_lower or "microsoft" in mx_lower:
                selectors.add("selector1")
                selectors.add("selector2")
            elif "mimecast" in mx_lower:
                selectors.add("mimecast20190104")
                selectors.add("mimecast")
            elif "protonmail" in mx_lower:
                selectors.add("protonmail")
                selectors.add("protonmail2")
                selectors.add("protonmail3")
            elif "zoho" in mx_lower:
                selectors.add("zoho")
                selectors.add("zmail")
    
    return list(selectors)


def get_mx_records(domain):
    """Retrieve MX records for a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [str(answer.exchange).lower() for answer in answers]
    except Exception:
        return []


def dkim_resolver(domain, prompt_selector=False):
    results = []
    
    if prompt_selector:
        custom = input("Enter custom DKIM selector(s) separated by commas: ")
        selectors = [s.strip() for s in custom.split(',') if s.strip()]
    else:
        # Use smart selector discovery
        mx_records = get_mx_records(domain)
        selectors = get_smart_selectors(domain, mx_records)
    
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        
        try:
            answers = dns.resolver.resolve(dkim_domain, "CNAME")
            for answer in answers:
                results.append({
                    "selector": selector,
                    "record": answer.to_text(),
                    "type": "CNAME"
                })
        except Exception:
            pass
        
        try:
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            for answer in answers:
                txt_value = answer.to_text()
                if "v=DKIM1" in txt_value or "k=" in txt_value or "p=" in txt_value:
                    results.append({
                        "selector": selector,
                        "record": txt_value,
                        "type": "TXT"
                    })
        except Exception:
            pass
    
    return results if results else None


def calculate_dkim_score(dkim_result):
    if dkim_result:
        return 21
    return 0


# =============================================================================
# MTA-STS FUNCTIONS
# =============================================================================

def validate_mta_sts_policy(domain, policy_content, mx_records):
    """Validate MTA-STS policy against RFC 8461."""
    issues = []
    warnings = []
    
    if not policy_content:
        return issues, warnings
    
    lines = policy_content.strip().split('\n')
    policy_data = {}
    policy_mx = []
    
    for line in lines:
        line = line.strip()
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()
            if key == 'mx':
                policy_mx.append(value)
            else:
                policy_data[key] = value
    
    # Check version
    if policy_data.get('version') != 'STSv1':
        issues.append({
            'severity': 'ERROR',
            'message': f"Invalid or missing version (found: {policy_data.get('version', 'none')})",
            'recommendation': 'Set version: STSv1'
        })
    
    # Check mode
    mode = policy_data.get('mode', '')
    if mode not in ['enforce', 'testing', 'none']:
        issues.append({
            'severity': 'ERROR',
            'message': f"Invalid mode: {mode}",
            'recommendation': 'Set mode to enforce, testing, or none'
        })
    
    # Check max_age
    max_age = policy_data.get('max_age', '0')
    try:
        max_age_int = int(max_age)
        if max_age_int < 86400:
            warnings.append({
                'severity': 'WARNING',
                'message': f"max_age too short ({max_age}s), minimum 1 day (86400s) recommended",
                'recommendation': 'Set max_age to at least 86400 (1 day), recommended 604800 (1 week)'
            })
        elif max_age_int < 604800:
            warnings.append({
                'severity': 'INFO',
                'message': f"max_age is {max_age}s, consider 1 week (604800s) for production",
                'recommendation': 'Increase max_age for better caching'
            })
    except ValueError:
        issues.append({
            'severity': 'ERROR',
            'message': f"Invalid max_age value: {max_age}",
            'recommendation': 'Set max_age to a numeric value in seconds'
        })
    
    # Check MX coverage
    if mx_records and policy_mx:
        for mx in mx_records:
            mx_clean = mx.rstrip('.').lower()
            covered = False
            for pattern in policy_mx:
                pattern_clean = pattern.lower()
                if pattern_clean.startswith('*.'):
                    # Wildcard match
                    wildcard_base = pattern_clean[2:]
                    if mx_clean.endswith(wildcard_base) or mx_clean == wildcard_base.lstrip('.'):
                        covered = True
                        break
                elif mx_clean == pattern_clean or mx_clean == pattern_clean.rstrip('.'):
                    covered = True
                    break
            
            if not covered:
                issues.append({
                    'severity': 'ERROR',
                    'message': f"MX '{mx_clean}' not covered by MTA-STS policy",
                    'recommendation': f"Add 'mx: {mx_clean}' or appropriate wildcard to policy"
                })
    
    return issues, warnings


def mta_sts_resolver(domain):
    result = {
        "dns_record": None,
        "policy": None,
        "mode": None,
        "mx": [],
        "max_age": None,
        "version": None,
        "issues": [],
        "warnings": [],
        "https_valid": None
    }
    
    # Get MX records for validation
    mx_records = get_mx_records(domain)
    
    try:
        mta_sts_domain = f"_mta-sts.{domain}"
        answers = dns.resolver.resolve(mta_sts_domain, 'TXT')
        for answer in answers:
            if "v=STSv1" in answer.to_text():
                result["dns_record"] = answer.to_text()
                break
    except Exception:
        pass
    
    try:
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        response = requests.get(policy_url, timeout=10, verify=True)
        result["https_valid"] = True
        
        if response.status_code == 200:
            result["policy"] = response.text
            lines = response.text.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith("version:"):
                    result["version"] = line.split(":")[1].strip()
                elif line.startswith("mode:"):
                    result["mode"] = line.split(":")[1].strip()
                elif line.startswith("mx:"):
                    result["mx"].append(line.split(":")[1].strip())
                elif line.startswith("max_age:"):
                    result["max_age"] = line.split(":")[1].strip()
            
            # Validate policy
            issues, warnings = validate_mta_sts_policy(domain, result["policy"], mx_records)
            result["issues"] = issues
            result["warnings"] = warnings
    except requests.exceptions.SSLError:
        result["https_valid"] = False
        result["issues"].append({
            'severity': 'CRITICAL',
            'message': 'MTA-STS policy URL has invalid SSL certificate',
            'recommendation': 'Fix SSL certificate for mta-sts subdomain'
        })
    except Exception:
        pass
    
    return result


def calculate_mta_sts_score(mta_sts_result):
    score = 0
    
    # Critical issues = 0 score
    critical_issues = [i for i in mta_sts_result.get("issues", []) if i.get('severity') == 'CRITICAL']
    if critical_issues:
        return 0
    
    if mta_sts_result["dns_record"]:
        score += 4
    
    if mta_sts_result["policy"]:
        score += 3
        if mta_sts_result["mode"] == "enforce":
            score += 5
        elif mta_sts_result["mode"] == "testing":
            score += 2
        if mta_sts_result["mx"]:
            score += 2
    
    # Deduct for errors (non-critical)
    error_issues = [i for i in mta_sts_result.get("issues", []) if i.get('severity') == 'ERROR']
    score -= len(error_issues) * 2
    
    return max(0, min(score, 14))


# =============================================================================
# TLS-RPT FUNCTIONS
# =============================================================================

def tlsrpt_resolver(domain):
    result = {
        "record": None,
        "rua": None
    }
    try:
        tlsrpt_domain = f"_smtp._tls.{domain}"
        answers = dns.resolver.resolve(tlsrpt_domain, 'TXT')
        for answer in answers:
            record = answer.to_text()
            if "v=TLSRPTv1" in record:
                result["record"] = record
                if "rua=" in record:
                    rua_part = record.split("rua=")[1]
                    result["rua"] = rua_part.split(";")[0].strip().strip('"')
                break
    except Exception:
        pass
    return result


def calculate_tlsrpt_score(tlsrpt_result):
    score = 0
    if tlsrpt_result["record"]:
        score += 5
        if tlsrpt_result["rua"]:
            score += 5
    return min(score, 10)


# =============================================================================
# BIMI FUNCTIONS
# =============================================================================

def fetch_vmc_certificate(vmc_url):
    try:
        response = requests.get(vmc_url, timeout=15)
        if response.status_code != 200:
            return None, f"HTTP {response.status_code}"
        pem_data = response.content
        certificate = x509.load_pem_x509_certificate(pem_data, default_backend())
        return certificate, None
    except requests.exceptions.Timeout:
        return None, "Timeout"
    except requests.exceptions.RequestException as e:
        return None, f"Request error: {str(e)}"
    except ValueError as e:
        return None, f"Certificate parse error: {str(e)}"
    except Exception as e:
        return None, f"Unknown error: {str(e)}"


def verify_vmc_validity(certificate):
    now = datetime.now(timezone.utc)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    is_valid = not_before <= now <= not_after
    days_remaining = (not_after - now).days if is_valid else 0
    return {
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "is_valid": is_valid,
        "days_remaining": days_remaining,
        "is_expired": now > not_after,
        "not_yet_valid": now < not_before
    }


def verify_vmc_issuer(certificate):
    issuer = certificate.issuer.rfc4514_string()
    is_authorized = any(ca.lower() in issuer.lower() for ca in AUTHORIZED_VMC_CA)
    ca_name = "Unknown"
    for ca in AUTHORIZED_VMC_CA:
        if ca.lower() in issuer.lower():
            ca_name = ca
            break
    return {
        "issuer": issuer,
        "ca_name": ca_name,
        "is_authorized": is_authorized
    }


def verify_vmc_domain(certificate, domain):
    domains_in_cert = []
    for attr in certificate.subject:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            domains_in_cert.append(attr.value.lower())
    try:
        san_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                domains_in_cert.append(name.value.lower())
    except x509.ExtensionNotFound:
        pass
    domain_lower = domain.lower()
    domain_match = False
    for cert_domain in domains_in_cert:
        if cert_domain == domain_lower:
            domain_match = True
            break
        if cert_domain.startswith("*."):
            wildcard_base = cert_domain[2:]
            if domain_lower.endswith(wildcard_base):
                domain_match = True
                break
    return {
        "domains_in_cert": domains_in_cert,
        "target_domain": domain,
        "domain_match": domain_match
    }


def verify_vmc_eku(certificate):
    """Verify VMC has BIMI EKU extension."""
    try:
        eku_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        eku_oids = [eku.dotted_string for eku in eku_ext.value]
        has_bimi_eku = BIMI_EKU_OID in eku_oids
        return {
            "eku_oids": eku_oids,
            "has_bimi_eku": has_bimi_eku
        }
    except x509.ExtensionNotFound:
        return {
            "eku_oids": [],
            "has_bimi_eku": False
        }


def verify_logo_url(logo_url):
    result = {
        "url": logo_url,
        "accessible": False,
        "content_type": None,
        "is_svg": False,
        "is_secure": False,
        "size_bytes": 0
    }
    if not logo_url:
        return result
    result["is_secure"] = logo_url.lower().startswith("https://")
    try:
        response = requests.get(logo_url, timeout=15)
        if response.status_code == 200:
            result["accessible"] = True
            result["content_type"] = response.headers.get("Content-Type", "")
            result["size_bytes"] = len(response.content)
            content_type = result["content_type"].lower()
            if "svg" in content_type:
                result["is_svg"] = True
            elif response.content[:100].decode('utf-8', errors='ignore').strip().startswith(("<svg", "<?xml")):
                result["is_svg"] = True
    except Exception:
        pass
    return result


def bimi_resolver(domain, dmarc_record):
    result = {
        "record": None,
        "logo_url": None,
        "vmc_url": None,
        "dmarc_compliant": False,
        "logo_check": None,
        "vmc_check": None
    }
    
    # Check DMARC compliance
    result["dmarc_compliant"] = check_dmarc_compliance(dmarc_record)
    
    try:
        bimi_domain = f"default._bimi.{domain}"
        answers = dns.resolver.resolve(bimi_domain, 'TXT')
        for answer in answers:
            record = answer.to_text()
            if "v=BIMI1" in record:
                result["record"] = record
                
                # Extract logo URL
                if "l=" in record:
                    l_match = re.search(r'l=([^;\s"]+)', record)
                    if l_match:
                        result["logo_url"] = l_match.group(1)
                
                # Extract VMC URL
                if "a=" in record:
                    a_match = re.search(r'a=([^;\s"]+)', record)
                    if a_match:
                        result["vmc_url"] = a_match.group(1)
                break
    except Exception:
        pass
    
    # Verify logo
    if result["logo_url"]:
        result["logo_check"] = verify_logo_url(result["logo_url"])
    
    # Verify VMC
    if result["vmc_url"]:
        cert, error = fetch_vmc_certificate(result["vmc_url"])
        if cert:
            result["vmc_check"] = {
                "found": True,
                "validity": verify_vmc_validity(cert),
                "issuer": verify_vmc_issuer(cert),
                "domain": verify_vmc_domain(cert, domain),
                "eku": verify_vmc_eku(cert)
            }
        else:
            result["vmc_check"] = {
                "found": False,
                "error": error
            }
    
    return result


def calculate_bimi_score(bimi_result):
    score = 0
    if not bimi_result["record"]:
        return 0
    score += 1
    if bimi_result["dmarc_compliant"]:
        score += 1
    if bimi_result["logo_check"]:
        if bimi_result["logo_check"]["accessible"]:
            score += 1
        if bimi_result["logo_check"]["is_svg"]:
            score += 1
        if bimi_result["logo_check"]["is_secure"]:
            score += 1
    if bimi_result["vmc_check"] and bimi_result["vmc_check"]["found"]:
        vmc = bimi_result["vmc_check"]
        if vmc["validity"] and vmc["validity"]["is_valid"]:
            score += 1
        if vmc["issuer"] and vmc["issuer"]["is_authorized"]:
            score += 1
        if vmc["domain"] and vmc["domain"]["domain_match"]:
            score += 1
    return min(score, 8)


# =============================================================================
# SCORING AND DISPLAY
# =============================================================================

def get_grade(score):
    if score >= 90:
        return "A+", "🟢"
    elif score >= 80:
        return "A", "🟢"
    elif score >= 70:
        return "B", "🟡"
    elif score >= 60:
        return "C", "🟡"
    elif score >= 50:
        return "D", "🟠"
    elif score >= 40:
        return "E", "🟠"
    else:
        return "F", "🔴"


def analyze_results(domain, spf_result, dmarc_result, dkim_result, mta_sts_result, tlsrpt_result, bimi_result, verbose=False):
    print(f"\n{'='*60}")
    print(f"  EMAIL SECURITY ANALYSIS: {domain}")
    print(f"{'='*60}\n")

    spf_score = calculate_spf_score(spf_result)
    dmarc_score = calculate_dmarc_score(dmarc_result)
    dkim_score = calculate_dkim_score(dkim_result)
    mta_sts_score = calculate_mta_sts_score(mta_sts_result)
    tlsrpt_score = calculate_tlsrpt_score(tlsrpt_result)
    bimi_score = calculate_bimi_score(bimi_result)

    total_score = spf_score + dmarc_score + dkim_score + mta_sts_score + tlsrpt_score + bimi_score
    grade, emoji = get_grade(total_score)

    # Parse DMARC for display
    dmarc_parsed = parse_dmarc_tags(dmarc_result) if dmarc_result else None

    # =========================================================================
    # SPF DISPLAY
    # =========================================================================
    print(f"📧 SPF ({spf_score}/20)")
    if spf_result:
        spf_record = spf_result.get('record') if isinstance(spf_result, dict) else spf_result[0]
        spf_mechanism = spf_result.get('mechanism') if isinstance(spf_result, dict) else spf_result[1]
        
        print(f"   Record: {spf_record}")
        print(f"   Mechanism: {spf_mechanism}")
        
        if isinstance(spf_result, dict):
            # Show null SPF status
            if spf_result.get('is_null_spf'):
                print(f"   ℹ️  Null SPF: Domain configured to send no email")
            
            # Show DNS lookup count
            dns_lookups = spf_result.get('dns_lookups', 0)
            lookup_indicator = "✅" if dns_lookups <= 7 else ("⚠️" if dns_lookups <= 10 else "❌")
            print(f"   DNS Lookups: {dns_lookups}/10 {lookup_indicator}")
            
            if verbose and spf_result.get('lookup_details'):
                for lookup in spf_result['lookup_details']:
                    print(f"      - {lookup['type']}: {lookup['value']}")
            
            # Show issues
            for issue in spf_result.get('issues', []):
                severity_icon = "🔴" if issue['severity'] == 'CRITICAL' else "❌"
                print(f"   {severity_icon} {issue['severity']}: {issue['message']}")
            
            for warning in spf_result.get('warnings', []):
                print(f"   ⚠️  {warning['severity']}: {warning['message']}")
    else:
        print("   ❌ No SPF record found")

    # =========================================================================
    # DMARC DISPLAY
    # =========================================================================
    print(f"\n📧 DMARC ({dmarc_score}/27)")
    if dmarc_result and dmarc_parsed:
        print(f"   Record: {dmarc_result}")
        
        effective = dmarc_parsed.get("effective", {})
        explicit = dmarc_parsed.get("explicit", {})
        
        # Policy
        policy = effective.get("p", "none")
        print(f"   Policy: {policy}")
        
        # Subdomain policy
        sp = effective.get("sp", policy)
        sp_source = "" if "sp" in explicit else " (inherited from p=)"
        print(f"   Subdomain Policy: {sp}{sp_source}")
        
        # Alignments
        adkim = effective.get("adkim", "r")
        adkim_source = "" if "adkim" in explicit else " (default)"
        adkim_full = "strict" if adkim == "s" else "relaxed"
        print(f"   DKIM Alignment: {adkim_full}{adkim_source}")
        
        aspf = effective.get("aspf", "r")
        aspf_source = "" if "aspf" in explicit else " (default)"
        aspf_full = "strict" if aspf == "s" else "relaxed"
        print(f"   SPF Alignment: {aspf_full}{aspf_source}")
        
        # Percentage
        pct = effective.get("pct", "100")
        pct_source = "" if "pct" in explicit else " (default)"
        print(f"   Percentage: {pct}%{pct_source}")
        
        # Reporting
        if "rua" in explicit:
            print(f"   Aggregate Reports (rua): {explicit['rua']}")
        else:
            print(f"   Aggregate Reports (rua): ❌ not configured")
        
        if "ruf" in explicit:
            print(f"   Forensic Reports (ruf): {explicit['ruf']}")
        else:
            print(f"   Forensic Reports (ruf): ❌ not configured")
    else:
        print("   ❌ No DMARC record found")

    # =========================================================================
    # DKIM DISPLAY
    # =========================================================================
    print(f"\n📧 DKIM ({dkim_score}/21)")
    if dkim_result:
        for entry in dkim_result:
            print(f"   ✅ Selector: {entry['selector']} ({entry['type']})")
            if verbose:
                print(f"      Record: {entry['record'][:80]}...")
    else:
        print("   ❌ No DKIM selectors found")

    # =========================================================================
    # MTA-STS DISPLAY
    # =========================================================================
    print(f"\n🔒 MTA-STS ({mta_sts_score}/14)")
    if mta_sts_result["dns_record"]:
        print(f"   DNS: {mta_sts_result['dns_record']}")
        
        if mta_sts_result["https_valid"] is not None:
            https_status = "✅ Valid" if mta_sts_result["https_valid"] else "❌ Invalid"
            print(f"   HTTPS Certificate: {https_status}")
        
        if mta_sts_result["version"]:
            print(f"   Version: {mta_sts_result['version']}")
        if mta_sts_result["mode"]:
            print(f"   Mode: {mta_sts_result['mode']}")
        if mta_sts_result["max_age"]:
            max_age_days = int(mta_sts_result["max_age"]) / 86400
            print(f"   Max Age: {mta_sts_result['max_age']}s ({max_age_days:.1f} days)")
        if mta_sts_result["mx"]:
            print(f"   MX Patterns: {', '.join(mta_sts_result['mx'])}")
        
        # Show issues
        for issue in mta_sts_result.get("issues", []):
            severity_icon = "🔴" if issue['severity'] == 'CRITICAL' else "❌"
            print(f"   {severity_icon} {issue['severity']}: {issue['message']}")
        
        for warning in mta_sts_result.get("warnings", []):
            print(f"   ⚠️  {warning['severity']}: {warning['message']}")
    else:
        print("   ❌ No MTA-STS record found")

    # =========================================================================
    # TLS-RPT DISPLAY
    # =========================================================================
    print(f"\n📊 TLS-RPT ({tlsrpt_score}/10)")
    if tlsrpt_result["record"]:
        print(f"   Record: {tlsrpt_result['record']}")
        if tlsrpt_result["rua"]:
            print(f"   Report URI: {tlsrpt_result['rua']}")
    else:
        print("   ❌ No TLS-RPT record found")

    # =========================================================================
    # BIMI DISPLAY
    # =========================================================================
    print(f"\n🎨 BIMI ({bimi_score}/8)")
    if bimi_result["record"]:
        print(f"   Record: {bimi_result['record']}")
        dmarc_status = "✅" if bimi_result["dmarc_compliant"] else "❌"
        print(f"   DMARC Compliant: {dmarc_status}")
        
        if bimi_result["logo_check"]:
            logo = bimi_result["logo_check"]
            logo_status = "✅" if logo["accessible"] else "❌"
            svg_status = "✅" if logo["is_svg"] else "❌"
            secure_status = "✅" if logo["is_secure"] else "❌"
            print(f"   Logo: {logo_status} Accessible | {svg_status} SVG | {secure_status} HTTPS")
            if logo["size_bytes"]:
                print(f"   Logo Size: {logo['size_bytes']} bytes")
        
        if bimi_result["vmc_check"]:
            vmc = bimi_result["vmc_check"]
            if vmc.get("found"):
                validity_status = "✅" if vmc["validity"]["is_valid"] else "❌"
                issuer_status = "✅" if vmc["issuer"]["is_authorized"] else "❌"
                domain_status = "✅" if vmc["domain"]["domain_match"] else "❌"
                print(f"   VMC: {validity_status} Valid | {issuer_status} {vmc['issuer']['ca_name']} | {domain_status} Domain Match")
                if vmc["validity"]["is_valid"]:
                    print(f"   VMC Expires: {vmc['validity']['days_remaining']} days remaining")
                if vmc.get("eku"):
                    eku_status = "✅" if vmc["eku"]["has_bimi_eku"] else "❌"
                    print(f"   BIMI EKU: {eku_status}")
            else:
                print(f"   VMC: ❌ Error - {vmc.get('error', 'Unknown error')}")
    else:
        print("   ❌ No BIMI record found")

    # =========================================================================
    # FINAL SCORE
    # =========================================================================
    print(f"\n{'='*60}")
    print(f"  TOTAL SCORE: {total_score}/100 - Grade: {emoji} {grade}")
    print(f"{'='*60}")

    print(f"\n📊 Score Breakdown:")
    print(f"   SPF:     {spf_score:2}/20  {'█' * (spf_score // 2)}{'░' * (10 - spf_score // 2)}")
    print(f"   DMARC:   {dmarc_score:2}/27  {'█' * (dmarc_score * 10 // 27)}{'░' * (10 - dmarc_score * 10 // 27)}")
    print(f"   DKIM:    {dkim_score:2}/21  {'█' * (dkim_score * 10 // 21)}{'░' * (10 - dkim_score * 10 // 21)}")
    print(f"   MTA-STS: {mta_sts_score:2}/14  {'█' * (mta_sts_score * 10 // 14)}{'░' * (10 - mta_sts_score * 10 // 14)}")
    print(f"   TLS-RPT: {tlsrpt_score:2}/10  {'█' * tlsrpt_score}{'░' * (10 - tlsrpt_score)}")
    print(f"   BIMI:    {bimi_score:2}/8   {'█' * (bimi_score * 10 // 8)}{'░' * (10 - bimi_score * 10 // 8)}")

    # =========================================================================
    # RECOMMENDATIONS
    # =========================================================================
    print(f"\n💡 Recommendations:")
    actions = []

    # SPF recommendations
    if spf_result:
        if isinstance(spf_result, dict):
            # Critical issues first
            for issue in spf_result.get('issues', []):
                actions.append(f"• 🔴 {issue['recommendation']}")
            
            # Warnings
            for warning in spf_result.get('warnings', []):
                actions.append(f"• ⚠️  {warning['recommendation']}")
            
            # Standard recommendations
            if not spf_result.get('is_null_spf'):
                if spf_result.get('mechanism') == "softfail":
                    actions.append("• Harden SPF: change '~all' to '-all' (hardfail)")
        else:
            # Legacy format
            if spf_result[1] == "softfail":
                actions.append("• Harden SPF: change '~all' to '-all' (hardfail)")
    else:
        actions.append("• Implement SPF record with '-all' (hardfail)")

    # DMARC recommendations
    if dmarc_result and dmarc_parsed:
        effective = dmarc_parsed.get("effective", {})
        explicit = dmarc_parsed.get("explicit", {})
        
        policy = effective.get("p", "none").lower()
        if policy == "none":
            actions.append("• 🔴 Upgrade DMARC policy from 'none' to 'quarantine' or 'reject'")
        elif policy == "quarantine":
            actions.append("• Consider upgrading DMARC policy from 'quarantine' to 'reject'")
        
        if "sp" not in explicit:
            actions.append("• Consider adding explicit subdomain policy (sp=reject)")
        
        if "rua" not in explicit:
            actions.append("• 🔴 Add DMARC aggregate reporting (rua=mailto:...)")
        
        if "ruf" not in explicit:
            actions.append("• Consider adding DMARC forensic reporting (ruf=)")
        
        if effective.get("adkim") != "s":
            actions.append("• Consider strict DKIM alignment (adkim=s) for enhanced security")
        if effective.get("aspf") != "s":
            actions.append("• Consider strict SPF alignment (aspf=s) for enhanced security")
    else:
        actions.append("• 🔴 Implement DMARC record with p=reject policy")

    # DKIM recommendations
    if dkim_score == 0:
        actions.append("• Implement DKIM signing for outgoing emails")

    # MTA-STS recommendations
    if mta_sts_score < 14:
        if mta_sts_score == 0:
            actions.append("• Implement MTA-STS (DNS record + policy file)")
        else:
            # Show specific MTA-STS issues
            for issue in mta_sts_result.get("issues", []):
                actions.append(f"• {issue['recommendation']}")
            for warning in mta_sts_result.get("warnings", []):
                actions.append(f"• {warning['recommendation']}")
            
            if mta_sts_result["mode"] != "enforce":
                actions.append("• Set MTA-STS mode to 'enforce'")

    # TLS-RPT recommendations
    if tlsrpt_score < 10:
        if tlsrpt_score == 0:
            actions.append("• Implement TLS-RPT (_smtp._tls record with rua=)")
        else:
            if not tlsrpt_result.get("rua"):
                actions.append("• Add reporting URI (rua=) to TLS-RPT record")

    # BIMI recommendations
    if bimi_score < 8:
        if bimi_score == 0:
            actions.append("• Consider implementing BIMI (default._bimi record with logo URL)")
        else:
            if not bimi_result.get("dmarc_compliant"):
                actions.append("• Set DMARC policy to p=quarantine or p=reject for BIMI compliance")
            if not bimi_result.get("vmc_url"):
                actions.append("• Consider adding VMC certificate for enhanced BIMI support")
            elif bimi_result.get("vmc_check") and not bimi_result["vmc_check"].get("found"):
                actions.append("• Fix VMC certificate URL (not accessible)")
            if bimi_result.get("vmc_check") and bimi_result["vmc_check"].get("found"):
                vmc = bimi_result["vmc_check"]
                if vmc.get("validity") and not vmc["validity"].get("is_valid"):
                    actions.append("• Renew VMC certificate (expired or not yet valid)")
                if vmc.get("issuer") and not vmc["issuer"].get("is_authorized"):
                    actions.append("• Obtain VMC from authorized CA (DigiCert, Entrust, GlobalSign, SSL.com, Sectigo)")

    if actions:
        for action in actions:
            print(f"  {action}")
    else:
        print("  ✅ All email security mechanisms properly configured!")

    print(f"\n{'='*60}\n")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    options = prog_parse()
    domain = options.domain
    verbose = options.verbose
    
    print(f"Analyzing domain: {domain}")
    
    spf_result = spf_resolver(domain)
    dmarc_result = dmarc_resolver(domain)
    dkim_result = dkim_resolver(domain, options.selector)
    mta_sts_result = mta_sts_resolver(domain)
    tlsrpt_result = tlsrpt_resolver(domain)
    bimi_result = bimi_resolver(domain, dmarc_result)

    analyze_results(domain, spf_result, dmarc_result, dkim_result, mta_sts_result, tlsrpt_result, bimi_result, verbose)
