# Author: Enzo LE NAIR
# Version: V2.0.2
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
import ipaddress
import sys

#Global DNS resolver (can be customized via -ns option)
DNS_RESOLVER = dns.resolver

AUTHORIZED_VMC_CA = [
    "DigiCert",
    "Entrust",
    "GlobalSign",
    "SSL.com",
    "Sectigo",
    "Comodo"
]

BIMI_EKU_OID = "1.3.6.1.5.5.7.3.31"

COMMON_SELECTORS = [
      "selector1", "selector2", "google", "k1", "k2", "ctct1", "ctct2", "sm", "s1", "s2",
        "sig1", "litesrv", "zendesk1", "zendesk2", "mail", "email", "dkim", "default", "class",
        "spop", "spop1024", "bfi", "alpha", "authsmtp", "pmta", "m", "main", "stigmate",
        "squaremail", "publickey", "proddkim", "ED-DKIM", "care", "0xdeadbeef", "yousendit",
        "scooby", "postfix.private", "primary", "mandrill", "dkimmail", "protonmail",
        "protonmail2", "protonmail3"
]



# ARGUMENT PARSER


def prog_parse():
    parser = ArgumentParser(
        prog="mailsecwatcher",
        description="Mail DNS-based protection checker - Analyzes SPF, DKIM, DMARC, MTA-STS, TLSRPT, and BIMI. Made with ♥ by Enzo LE NAIR.",
        usage="%(prog)s [options] -d domain_name"
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Domain to analyze"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "-s", "--selector",
        action="store_true",
        help="Prompt for custom DKIM selector(s)"
    )
    parser.add_argument(
        "-ns", "--nameserver",
        help="Custom DNS nameserver to use (e.g., 8.8.8.8)"
    )
    return parser.parse_args()



# SPF FUNCTIONS


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
    if "+all" in spf_lower or re.search(r'(?:^v=spf1\s+.*\s|^v=spf1\s+)all(?:\s|$)', spf_lower):
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
    lookup_count, _ = count_spf_dns_lookups(spf_record)
    if lookup_count > 10:
        issues.append({
            'severity': 'ERROR',
            'message': f'SPF DNS lookups ({lookup_count}) exceeds limit of 10 (RFC 7208)',
            'recommendation': 'Reduce includes or use ip4/ip6 mechanisms'
        })
    elif lookup_count > 7:
        warnings.append({
            'severity': 'WARNING',
            'message': f'SPF DNS lookups ({lookup_count}) is close to limit of 10',
            'recommendation': 'Consider reducing includes to avoid future issues'
        })
    
    return issues, warnings, is_null_spf


def resolve_spf_redirect(domain, max_depth=10, visited=None):
    """
    Recursively resolve SPF redirect modifier.
    Returns detailed information about the redirect chain.
    """
    if visited is None:
        visited = []
    
    # Protection contre les boucles infinies
    if domain.lower() in [d.lower() for d in visited]:
        return {
            'target': domain,
            'record': None,
            'mechanism': 'permerror',
            'issues': [],
            'warnings': [],
            'dns_lookups': 0,
            'lookup_details': [],
            'is_null_spf': False,
            'error': f"Redirect loop detected: {' -> '.join(visited)} -> {domain}",
            'chain': visited
        }
    
    if max_depth <= 0:
        return {
            'target': domain,
            'record': None,
            'mechanism': 'permerror',
            'issues': [],
            'warnings': [],
            'dns_lookups': 0,
            'lookup_details': [],
            'is_null_spf': False,
            'error': f"Too many redirects (exceeded max depth): {' -> '.join(visited)}",
            'chain': visited
        }
    
    visited.append(domain)

    try:
        answers = DNS_RESOLVER.resolve(domain, 'TXT')
        spf = None
        for answer in answers:
            txt = answer.to_text()
            if "v=spf1" in txt:
                spf = txt
                break
        
        if not spf:
            return {
                'target': domain,
                'record': None,
                'mechanism': 'permerror',
                'issues': [],
                'warnings': [],
                'dns_lookups': 0,
                'lookup_details': [],
                'is_null_spf': False,
                'error': f"No SPF record found at redirect target: {domain}",
                'chain': visited
            }
        
        spf_clean = spf.replace('"', '').strip()
        spf_lower = spf_clean.lower()
        
        mechanism_map = {
            "-all": "hardfail",
            "~all": "softfail",
            "?all": "neutral",
            "+all": "pass"
        }
        
        # Check for explicit 'all' mechanism
        found_mechanism = None
        for pattern, meca in mechanism_map.items():
            if pattern in spf_lower:
                found_mechanism = meca
                break
        
        # Check for bare "all" (defaults to +all)
        if not found_mechanism and re.search(r'(?:^v=spf1\s+.*\s|^v=spf1\s+)all(?:\s|$)', spf_lower):
            found_mechanism = "pass"
        
        # If we found an 'all' mechanism, analyze this record
        if found_mechanism:
            issues, warnings, is_null_spf = analyze_spf_security(spf)
            lookup_count, lookups = count_spf_dns_lookups(spf)
            
            return {
                'target': domain,
                'record': spf_clean,
                'mechanism': found_mechanism,
                'issues': issues,
                'warnings': warnings,
                'dns_lookups': lookup_count,
                'lookup_details': lookups,
                'is_null_spf': is_null_spf,
                'error': None,
                'chain': visited
            }
        
        # No 'all' found - check for another redirect
        redirect_match = re.search(r'redirect=([^\s]+)', spf_lower)
        if redirect_match:
            next_domain = redirect_match.group(1)
            nested_result = resolve_spf_redirect(next_domain, max_depth - 1, visited)
            
            # Accumulate DNS lookups from this level
            current_lookups, current_details = count_spf_dns_lookups(spf)
            
            if nested_result.get('dns_lookups') is not None:
                nested_result['dns_lookups'] += current_lookups
                nested_result['lookup_details'] = current_details + nested_result.get('lookup_details', [])
            
            # Store intermediate record for display
            if 'intermediate_records' not in nested_result:
                nested_result['intermediate_records'] = []
            nested_result['intermediate_records'].insert(0, {
                'domain': domain,
                'record': spf_clean
            })
            
            return nested_result
        
        # No 'all' and no 'redirect' = neutral (RFC 7208 Section 4.7)
        issues, warnings, is_null_spf = analyze_spf_security(spf)
        lookup_count, lookups = count_spf_dns_lookups(spf)
        
        warnings.append({
            'severity': 'WARNING',
            'message': f"No 'all' mechanism in redirect target ({domain}) - defaults to neutral",
            'recommendation': 'Add -all or ~all to the SPF record'
        })
        
        return {
            'target': domain,
            'record': spf_clean,
            'mechanism': 'neutral',
            'issues': issues,
            'warnings': warnings,
            'dns_lookups': lookup_count,
            'lookup_details': lookups,
            'is_null_spf': is_null_spf,
            'error': None,
            'chain': visited
        }
    
    except dns.resolver.NXDOMAIN:
        return {
            'target': domain,
            'record': None,
            'mechanism': 'permerror',
            'issues': [],
            'warnings': [],
            'dns_lookups': 0,
            'lookup_details': [],
            'is_null_spf': False,
            'error': f"Redirect domain does not exist: {domain}",
            'chain': visited
        }
    except dns.resolver.NoAnswer:
        return {
            'target': domain,
            'record': None,
            'mechanism': 'permerror',
            'issues': [],
            'warnings': [],
            'dns_lookups': 0,
            'lookup_details': [],
            'is_null_spf': False,
            'error': f"No TXT records at redirect target: {domain}",
            'chain': visited
        }
    except dns.resolver.NoNameservers:
        return {
            'target': domain,
            'record': None,
            'mechanism': 'temperror',
            'issues': [],
            'warnings': [],
            'dns_lookups': 0,
            'lookup_details': [],
            'is_null_spf': False,
            'error': f"No nameservers available for: {domain}",
            'chain': visited
        }
    except Exception as e:
        return {
            'target': domain,
            'record': None,
            'mechanism': 'temperror',
            'issues': [],
            'warnings': [],
            'dns_lookups': 0,
            'lookup_details': [],
            'is_null_spf': False,
            'error': f"Error resolving {domain}: {str(e)}",
            'chain': visited
        }


def get_spf_mechanism(spf_record, original_domain=None):
    """
    Determine the effective SPF mechanism, following redirects if necessary.
    Returns: (mechanism, redirect_info)
    """
    mechanism_map = {
        "-all": "hardfail",
        "~all": "softfail",
        "?all": "neutral",
        "+all": "pass"
    }
    
    if not spf_record:
        return None, None
    
    spf_clean = spf_record.replace('"', '').strip()
    spf_lower = spf_clean.lower()
    
    # Check for explicit 'all' mechanism first
    for pattern, meca in mechanism_map.items():
        if pattern in spf_lower:
            return meca, None
    
    # Check for bare "all" without qualifier (defaults to +all)
    if re.search(r'(?:^v=spf1\s+.*\s|^v=spf1\s+)all(?:\s|$)', spf_lower):
        return "pass", None
    
    # No 'all' found - check for redirect modifier
    redirect_match = re.search(r'redirect=([^\s]+)', spf_lower)
    if redirect_match:
        redirect_domain = redirect_match.group(1)
        redirect_result = resolve_spf_redirect(redirect_domain)
        return redirect_result.get('mechanism'), redirect_result
    
    # No 'all' and no 'redirect' = neutral (RFC 7208 Section 4.7)
    return "neutral", {
        'note': "No 'all' mechanism or 'redirect' modifier found - defaults to neutral per RFC 7208"
    }


def has_spf_mechanisms(spf_record):
    """Check if SPF record contains valid mechanisms indicating proper configuration."""
    if not spf_record:
        return False
    
    spf_lower = spf_record.lower()
    
    direct_mechanisms = ["include:", "ip4:", "ip6:", "redirect=", "exists:", "ptr"]
    if any(m in spf_lower for m in direct_mechanisms):
        return True
    
    a_pattern = r'(?:^v=spf1\s+|\s+)[+\-~?]?a(?:[:\/\s]|$)'
    mx_pattern = r'(?:^v=spf1\s+|\s+)[+\-~?]?mx(?:[:\/\s]|$)'
    
    if re.search(a_pattern, spf_lower):
        return True
    if re.search(mx_pattern, spf_lower):
        return True
    
    return False


def spf_resolver(domain):
    """
    Resolve and analyze SPF record for a domain.
    Properly handles redirect modifier according to RFC 7208.
    """
    try:
        answers = DNS_RESOLVER.resolve(domain, 'TXT')
        spf = None
        for answer in answers:
            txt = answer.to_text()
            if "v=spf1" in txt:
                spf = txt
                break
        
        if spf:
            spf_clean = spf.replace('"', '').strip()
            
            # Analyze security of the original record
            issues, warnings, is_null_spf = analyze_spf_security(spf)
            lookup_count, lookups = count_spf_dns_lookups(spf)
            
            # Get mechanism (following redirects if necessary)
            spf_meca, redirect_info = get_spf_mechanism(spf, domain)
            
            # Merge redirect analysis if present
            if redirect_info and redirect_info.get('record'):
                redirect_issues = redirect_info.get('issues', [])
                redirect_warnings = redirect_info.get('warnings', [])
                
                for issue in redirect_issues:
                    issue['message'] = f"[Redirect → {redirect_info.get('target')}] {issue['message']}"
                    issues.append(issue)
                
                for warning in redirect_warnings:
                    warning['message'] = f"[Redirect → {redirect_info.get('target')}] {warning['message']}"
                    warnings.append(warning)
                
                redirect_lookups = redirect_info.get('dns_lookups', 0)
                total_lookups = lookup_count + redirect_lookups
                
                if total_lookups > 10:
                    issues.append({
                        'severity': 'ERROR',
                        'message': f'Total SPF DNS lookups ({total_lookups}) exceeds limit of 10 (local: {lookup_count}, redirect chain: {redirect_lookups})',
                        'recommendation': 'Reduce includes or use ip4/ip6 mechanisms'
                    })
                
                lookup_count = total_lookups
                lookups = lookups + redirect_info.get('lookup_details', [])
            
            elif redirect_info and redirect_info.get('error'):
                issues.append({
                    'severity': 'ERROR',
                    'message': f"Redirect error: {redirect_info['error']}",
                    'recommendation': 'Verify the redirect target domain has a valid SPF record'
                })
            
            elif redirect_info and redirect_info.get('note'):
                warnings.append({
                    'severity': 'WARNING',
                    'message': redirect_info['note'],
                    'recommendation': 'Add explicit -all or ~all mechanism'
                })
            
            return {
                'record': spf_clean,
                'mechanism': spf_meca,
                'issues': issues,
                'warnings': warnings,
                'is_null_spf': is_null_spf,
                'dns_lookups': lookup_count,
                'lookup_details': lookups,
                'redirect_info': redirect_info
            }
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return None
    except Exception:
        return None


def calculate_spf_score(spf_result):
    """Calculate SPF score with security checks and redirect handling."""
    if not spf_result:
        return 0
    
    if isinstance(spf_result, dict):
        spf_record = spf_result.get('record')
        spf_mechanism = spf_result.get('mechanism')
        issues = spf_result.get('issues', [])
        is_null_spf = spf_result.get('is_null_spf', False)
        redirect_info = spf_result.get('redirect_info')
    else:
        spf_record, spf_mechanism = spf_result
        issues = []
        is_null_spf = False
        redirect_info = None
    
    if not spf_record:
        return 0
    
    critical_issues = [i for i in issues if i.get('severity') == 'CRITICAL']
    if critical_issues:
        return 0
    
    if redirect_info and redirect_info.get('error'):
        return 3
    
    if is_null_spf:
        return 20
    
    if redirect_info and redirect_info.get('is_null_spf'):
        return 20
    
    error_issues = [i for i in issues if i.get('severity') == 'ERROR']
    if error_issues:
        return 5
    
    score = 5
    
    if spf_mechanism == "hardfail":
        score += 12
    elif spf_mechanism == "softfail":
        score += 7
    elif spf_mechanism == "neutral":
        score += 2
    elif spf_mechanism == "pass":
        score += 0
    elif spf_mechanism in ["permerror", "temperror"]:
        score += 0
    
    if has_spf_mechanisms(spf_result.get('record', '')):
        score += 3
    
    return min(score, 20)



# DMARC FUNCTIONS


def parse_dmarc_tags(dmarc_record):
    """Parse DMARC record and return tags with effective values (including defaults)."""
    if not dmarc_record:
        return {}
    
    defaults = {
        "p": None,
        "sp": None,
        "adkim": "r",
        "aspf": "r",
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
    
    effective = defaults.copy()
    for key in tags:
        effective[key] = tags[key]
    
    if "sp" not in tags and "p" in tags:
        effective["sp"] = tags["p"]
    
    return {
        "explicit": tags,
        "effective": effective
    }


def dmarc_resolver(domain):
    """Resolve DMARC record for a domain."""
    try:
        answers = DNS_RESOLVER.resolve(f"_dmarc.{domain}", 'TXT')
        for answer in answers:
            txt = answer.to_text().replace('"', '').strip()
            if "v=DMARC1" in txt:
                return txt
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return None
    except Exception:
        return None


def calculate_dmarc_score(dmarc_result):
    """Calculate DMARC score based on policy configuration."""
    if not dmarc_result:
        return 0
    
    parsed = parse_dmarc_tags(dmarc_result)
    if not parsed:
        return 0
    
    effective = parsed.get("effective", {})
    explicit = parsed.get("explicit", {})
    
    score = 2
    
    policy = effective.get("p", "none").lower()
    if policy == "reject":
        score += 10
    elif policy == "quarantine":
        score += 7
    elif policy == "none":
        score += 0
    
    sp = effective.get("sp", "none").lower()
    if sp == "reject":
        score += 5
    elif sp == "quarantine":
        score += 3
    elif sp == "none":
        score += 0
    
    if "rua" in explicit:
        score += 4
    
    if "ruf" in explicit:
        score += 2
    
    if effective.get("adkim") == "s":
        score += 2
    
    if effective.get("aspf") == "s":
        score += 2
    
    return min(score, 27)



# DKIM FUNCTIONS


def dkim_resolver(domain, custom_selectors=None):
    """Resolve DKIM records for a domain using common selectors."""
    selectors_to_check = COMMON_SELECTORS.copy()
    
    if custom_selectors:
        for selector in custom_selectors:
            if selector not in selectors_to_check:
                selectors_to_check.insert(0, selector)
    
    found_dkim = []
    
    for selector in selectors_to_check:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = DNS_RESOLVER.resolve(dkim_domain, 'TXT')
            for answer in answers:
                txt = answer.to_text().replace('"', '').strip()
                if "v=DKIM1" in txt or "k=" in txt or "p=" in txt:
                    found_dkim.append({
                        "selector": selector,
                        "record": txt
                    })
                    break
        except Exception:
            continue
    
    return found_dkim if found_dkim else None


def calculate_dkim_score(dkim_result):
    """Calculate DKIM score based on found selectors."""
    if not dkim_result:
        return 0
    
    count = len(dkim_result)
    
    if count >= 3:
        return 21
    elif count == 2:
        return 17
    elif count == 1:
        return 12
    
    return 0



# MTA-STS FUNCTIONS


def mta_sts_resolver(domain):
    """Resolve and analyze MTA-STS configuration for a domain."""
    result = {
        'record': None,
        'policy': False,
        'policy_content': None,
        'issues': [],
        'warnings': []
    }

    try:
        answers = DNS_RESOLVER.resolve(f"_mta-sts.{domain}", 'TXT')
        for answer in answers:
            txt = answer.to_text().replace('"', '').strip()
            if "v=STSv1" in txt:
                result['record'] = txt
                break
    except Exception:
        return result
    
    if result['record']:
        try:
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            response = requests.get(policy_url, timeout=10)
            if response.status_code == 200:
                result['policy'] = True
                result['policy_content'] = response.text
                
                if 'mode:' not in response.text.lower():
                    result['issues'].append({
                        'message': 'MTA-STS policy missing mode directive'
                    })
                elif 'mode: none' in response.text.lower():
                    result['warnings'].append({
                        'message': 'MTA-STS mode is set to none (no enforcement)'
                    })
                elif 'mode: testing' in response.text.lower():
                    result['warnings'].append({
                        'message': 'MTA-STS is in testing mode (not enforcing)'
                    })
        except Exception:
            result['issues'].append({
                'message': 'Could not fetch MTA-STS policy file'
            })
    
    return result


def calculate_mta_sts_score(mta_sts_result):
    """Calculate MTA-STS score."""
    if not mta_sts_result or not mta_sts_result.get('record'):
        return 0
    
    score = 4
    
    if mta_sts_result.get('policy'):
        score += 4
        
        policy_content = mta_sts_result.get('policy_content', '').lower()
        if 'mode: enforce' in policy_content:
            score += 4
        elif 'mode: testing' in policy_content:
            score += 2
    
    return min(score, 12)



# TLS-RPT FUNCTIONS


def tlsrpt_resolver(domain):
    """Resolve TLS-RPT record for a domain."""
    result = {
        'record': None,
        'rua': None
    }

    try:
        answers = DNS_RESOLVER.resolve(f"_smtp._tls.{domain}", 'TXT')
        for answer in answers:
            txt = answer.to_text().replace('"', '').strip()
            if "v=TLSRPTv1" in txt:
                result['record'] = txt
                
                rua_match = re.search(r'rua=([^\s;]+)', txt)
                if rua_match:
                    result['rua'] = rua_match.group(1)
                break
    except Exception:
        pass
    
    return result


def calculate_tlsrpt_score(tlsrpt_result):
    """Calculate TLS-RPT score."""
    if not tlsrpt_result or not tlsrpt_result.get('record'):
        return 0
    
    score = 6
    
    if tlsrpt_result.get('rua'):
        score += 6
    
    return min(score, 12)



# BIMI FUNCTIONS


def check_dmarc_compliance(dmarc_result):
    """Check if DMARC policy is BIMI-compliant (quarantine or reject)."""
    if not dmarc_result:
        return False
    
    parsed = parse_dmarc_tags(dmarc_result)
    if not parsed:
        return False
    
    policy = parsed.get("effective", {}).get("p", "none").lower()
    return policy in ["quarantine", "reject"]


def verify_vmc_validity(certificate):
    """Verify VMC certificate validity dates."""
    now = datetime.now(timezone.utc)
    not_before = certificate.not_valid_before_utc if hasattr(certificate, 'not_valid_before_utc') else certificate.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = certificate.not_valid_after_utc if hasattr(certificate, 'not_valid_after_utc') else certificate.not_valid_after.replace(tzinfo=timezone.utc)
    
    is_valid = not_before <= now <= not_after
    days_remaining = (not_after - now).days if is_valid else 0
    
    return {
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "is_valid": is_valid,
        "days_remaining": days_remaining
    }


def verify_vmc_issuer(certificate):
    """Verify VMC is issued by an authorized CA."""
    try:
        issuer_cn = None
        for attr in certificate.issuer:
            if attr.oid.dotted_string == "2.5.4.3":
                issuer_cn = attr.value
                break
        
        if not issuer_cn:
            issuer_cn = certificate.issuer.rfc4514_string()
        
        is_authorized = any(ca.lower() in issuer_cn.lower() for ca in AUTHORIZED_VMC_CA)
        
        return {
            "issuer": issuer_cn,
            "is_authorized": is_authorized
        }
    except Exception:
        return {
            "issuer": "Unknown",
            "is_authorized": False
        }


def verify_vmc_domain(certificate, domain):
    """Verify VMC covers the domain."""
    try:
        san_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_domains = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)]
        
        domain_match = False
        for san in san_domains:
            if san.lower() == domain.lower():
                domain_match = True
                break
            if san.startswith('*.') and domain.lower().endswith(san[1:].lower()):
                domain_match = True
                break
        
        return {
            "san_domains": san_domains,
            "domain_match": domain_match
        }
    except Exception:
        return {
            "san_domains": [],
            "domain_match": False,
            "error": "Could not parse SAN extension"
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
    """Verify BIMI logo URL."""
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


def fetch_vmc_certificate(vmc_url):
    """Fetch and parse VMC certificate."""
    try:
        response = requests.get(vmc_url, timeout=15)
        if response.status_code != 200:
            return None, f"HTTP {response.status_code}"
        
        pem_data = response.content
        
        if b"-----BEGIN CERTIFICATE-----" in pem_data:
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            return cert, None
        else:
            return None, "Invalid certificate format"
    except Exception as e:
        return None, str(e)


def bimi_resolver(domain, dmarc_result):
    """Resolve and analyze BIMI record for a domain."""
    result = {
        'record': None,
        'logo_url': None,
        'vmc_url': None,
        'dmarc_compliant': check_dmarc_compliance(dmarc_result),
        'logo_check': None,
        'vmc_check': None
    }

    try:
        answers = DNS_RESOLVER.resolve(f"default._bimi.{domain}", 'TXT')
        for answer in answers:
            txt = answer.to_text().replace('"', '').strip()
            if "v=BIMI1" in txt:
                result['record'] = txt
                
                logo_match = re.search(r'l=([^\s;]+)', txt)
                if logo_match:
                    result['logo_url'] = logo_match.group(1)
                
                vmc_match = re.search(r'a=([^\s;]+)', txt)
                if vmc_match:
                    result['vmc_url'] = vmc_match.group(1)
                break
    except Exception:
        return result
    
    if result['logo_url']:
        result['logo_check'] = verify_logo_url(result['logo_url'])
    
    if result['vmc_url']:
        cert, error = fetch_vmc_certificate(result['vmc_url'])
        if cert:
            result['vmc_check'] = {
                "found": True,
                "validity": verify_vmc_validity(cert),
                "issuer": verify_vmc_issuer(cert),
                "domain": verify_vmc_domain(cert, domain),
                "eku": verify_vmc_eku(cert)
            }
        else:
            result['vmc_check'] = {
                "found": False,
                "error": error
            }
    
    return result


def calculate_bimi_score(bimi_result):
    """Calculate BIMI score."""
    score = 0
    
    if not bimi_result or not bimi_result.get("record"):
        return 0
    
    score += 1
    
    if bimi_result.get("dmarc_compliant"):
        score += 1
    
    if bimi_result.get("logo_check"):
        if bimi_result["logo_check"].get("accessible"):
            score += 1
        if bimi_result["logo_check"].get("is_svg"):
            score += 1
        if bimi_result["logo_check"].get("is_secure"):
            score += 1
    
    if bimi_result.get("vmc_check") and bimi_result["vmc_check"].get("found"):
        vmc = bimi_result["vmc_check"]
        if vmc.get("validity") and vmc["validity"].get("is_valid"):
            score += 1
        if vmc.get("issuer") and vmc["issuer"].get("is_authorized"):
            score += 1
        if vmc.get("domain") and vmc["domain"].get("domain_match"):
            score += 1
    
    return min(score, 8)



# SCORING AND DISPLAY


def get_grade(score):
    """Get letter grade based on score."""
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


def categorize_recommendations(spf_result, dmarc_result, dkim_score, mta_sts_result, tlsrpt_result, bimi_result):
    """Categorize recommendations by priority level.

    Returns a dictionary with 4 categories: critical, high, medium, low
    Each category contains a list of recommendation strings.
    """
    critical = []
    high = []
    medium = []
    low = []

    dmarc_parsed = parse_dmarc_tags(dmarc_result) if dmarc_result else None

    #SPF recommendations
    if not spf_result:
        critical.append("Implement SPF record to prevent email spoofing")
    else:
        mechanism = spf_result.get('mechanism')

        if mechanism == 'pass':
            critical.append("CRITICAL: Remove +all from SPF - it allows anyone to spoof your domain")
        elif mechanism == 'neutral':
            critical.append("SPF defaults to neutral - add -all or ~all for protection")

        if spf_result.get('redirect_info') and spf_result['redirect_info'].get('error'):
            critical.append("Fix SPF redirect - target domain has no valid SPF record")

        lookup_count = spf_result.get('dns_lookups', 0)
        if lookup_count > 10:
            critical.append(f"Reduce SPF DNS lookups from {lookup_count} to 10 or fewer")
        elif lookup_count > 7:
            high.append(f"Consider reducing SPF DNS lookups ({lookup_count}/10) to avoid future issues")

        if mechanism == 'softfail':
            high.append("Consider upgrading SPF from ~all (softfail) to -all (hardfail)")

    #DMARC recommendations
    if dmarc_result and dmarc_parsed:
        effective = dmarc_parsed.get("effective", {})
        explicit = dmarc_parsed.get("explicit", {})

        policy = effective.get("p", "none").lower()

        if "rua" not in explicit:
            critical.append("Add DMARC aggregate reporting (rua=mailto:...)")

        if policy == "none":
            critical.append("Upgrade DMARC policy from 'none' to 'quarantine' or 'reject'")
        elif policy == "quarantine":
            high.append("Consider upgrading DMARC policy from 'quarantine' to 'reject'")

        if "sp" not in explicit:
            high.append("Consider adding explicit subdomain policy (sp=reject)")

        if "ruf" not in explicit:
            high.append("Consider adding DMARC forensic reporting (ruf=mailto:...)")

        if effective.get("adkim") != "s":
            medium.append("Consider strict DKIM alignment (adkim=s) for enhanced security")
        if effective.get("aspf") != "s":
            medium.append("Consider strict SPF alignment (aspf=s) for enhanced security")
    else:
        critical.append("Implement DMARC record with p=reject policy")

    #DKIM recommendations
    if dkim_score == 0:
        critical.append("Implement DKIM signing for outgoing emails")

    #MTA-STS recommendations
    if not mta_sts_result or not mta_sts_result.get('record'):
        low.append("Consider implementing MTA-STS for transport security")
    elif mta_sts_result.get('policy_content'):
        if 'mode: testing' in mta_sts_result['policy_content'].lower():
            medium.append("Upgrade MTA-STS from testing to enforce mode")

    #TLS-RPT recommendations
    if not tlsrpt_result or not tlsrpt_result.get('record'):
        low.append("Add TLS-RPT record for TLS failure reporting")

    #BIMI recommendations
    if not bimi_result or not bimi_result.get('record'):
        if dmarc_result and dmarc_parsed:
            policy = dmarc_parsed.get("effective", {}).get("p", "none").lower()
            if policy in ["quarantine", "reject"]:
                low.append("Consider implementing BIMI for brand visibility")
            else:
                low.append("BIMI requires DMARC with p=quarantine or p=reject")
        else:
            low.append("BIMI requires DMARC with p=quarantine or p=reject")

    return {
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low
    }


def analyze_results(domain, spf_result, dmarc_result, dkim_result, mta_sts_result, tlsrpt_result, bimi_result, verbose=False):
    """Display analysis results."""
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
    
    dmarc_parsed = parse_dmarc_tags(dmarc_result) if dmarc_result else None
    
    # OVERALL SCORE
    
    print(f"{emoji} OVERALL SCORE: {total_score}/100 (Grade: {grade})")
    print(f"\n{'─'*60}")
    
    # SPF DISPLAY - MODIFIÉ POUR AFFICHER LE SPF DU REDIRECT:  voir semaine pro si ok
    print(f"\n📧 SPF ({spf_score}/20)")
    if spf_result:
        print(f"   Record: {spf_result['record']}")
        
        redirect_info = spf_result.get('redirect_info')
        
        if redirect_info and redirect_info.get('record'):
            # Affichage avec redirect résolu
            print(f"   Local mechanism: (none - uses redirect)")
            
            # Afficher la chaîne de redirects
            chain = redirect_info.get('chain', [])
            if chain:
                print(f"   ↪️  Redirect chain: {' → '.join(chain)}")
            
            # TOUJOURS afficher l'enregistrement SPF du redirect (pas seulement en verbose)
            print(f"   📋 Redirected SPF ({redirect_info.get('target')}):")
            redirect_record = redirect_info.get('record', '')
            # Afficher sur plusieurs lignes si trop long
            if len(redirect_record) > 70:
                print(f"      {redirect_record[:70]}")
                remaining = redirect_record[70:]
                while remaining:
                    print(f"      {remaining[:70]}")
                    remaining = remaining[70:]
            else:
                print(f"      {redirect_record}")
            
            print(f"   Effective mechanism: {spf_result['mechanism']} (from redirect)")
            
            # Afficher les enregistrements intermédiaires si chaîne de redirects
            if verbose and redirect_info.get('intermediate_records'):
                print(f"   📑 Intermediate records:")
                for intermediate in redirect_info['intermediate_records']:
                    print(f"      {intermediate['domain']}:")
                    print(f"         {intermediate['record']}")
        
        elif redirect_info and redirect_info.get('error'):
            # Redirect avec erreur
            print(f"   ↪️  Redirect target: {redirect_info.get('target', 'unknown')}")
            print(f"   ❌ Redirect error: {redirect_info['error']}")
            print(f"   Effective mechanism: {spf_result['mechanism']}")
        
        else:
            # Pas de redirect
            print(f"   Mechanism: {spf_result['mechanism']}")
        
        # DNS Lookups
        lookup_count = spf_result.get('dns_lookups', 0)
        lookup_icon = "✅" if lookup_count <= 10 else "❌"
        print(f"   DNS Lookups: {lookup_icon} {lookup_count}/10")
        
        if verbose and spf_result.get('lookup_details'):
            for lookup in spf_result['lookup_details']:
                print(f"      - {lookup['type']}: {lookup['value']}")
        
        # Issues
        for issue in spf_result.get('issues', []):
            severity_icon = "🔴" if issue['severity'] == 'CRITICAL' else "❌"
            print(f"   {severity_icon} {issue['severity']}: {issue['message']}")
            if verbose and issue.get('recommendation'):
                print(f"      💡 {issue['recommendation']}")
        
        # Warnings
        for warning in spf_result.get('warnings', []):
            icon = "⚠️" if warning['severity'] == 'WARNING' else "ℹ️"
            print(f"   {icon} {warning['message']}")
            if verbose and warning.get('recommendation'):
                print(f"      💡 {warning['recommendation']}")
    else:
        print("   ❌ No SPF record found")
    
    # DMARC DISPLAY
    print(f"\n🛡️  DMARC ({dmarc_score}/27)")
    if dmarc_result and dmarc_parsed:
        effective = dmarc_parsed.get("effective", {})
        explicit = dmarc_parsed.get("explicit", {})
        
        print(f"   Record: {dmarc_result}")
        print(f"   Policy (p): {effective.get('p', 'none')}")
        
        if "sp" in explicit:
            print(f"   Subdomain Policy (sp): {effective.get('sp')} (explicit)")
        else:
            print(f"   Subdomain Policy (sp): {effective.get('sp', 'none')} (inherited from p)")
        
        print(f"   DKIM Alignment (adkim): {effective.get('adkim', 'r')} ({'strict' if effective.get('adkim') == 's' else 'relaxed'})")
        print(f"   SPF Alignment (aspf): {effective.get('aspf', 'r')} ({'strict' if effective.get('aspf') == 's' else 'relaxed'})")
        
        pct = effective.get('pct', '100')
        pct_source = "(explicit)" if "pct" in explicit else "(default)"
        print(f"   Percentage (pct): {pct}% {pct_source}")
        
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
    
    # DKIM DISPLAY
    print(f"\n🔑 DKIM ({dkim_score}/21)")
    if dkim_result:
        selector_count = len(dkim_result)
        print(f"   Found {selector_count} selector(s):")
        for dkim in dkim_result:
            print(f"   ✅ {dkim['selector']}")
            if verbose:
                record = dkim['record']
                if len(record) > 80:
                    print(f"      {record[:80]}...")
                else:
                    print(f"      {record}")

        #Display scoring justification
        if selector_count == 1:
            print(f"   Scoring: 1 selector = 12pts (consider adding more for redundancy)")
        elif selector_count == 2:
            print(f"   Scoring: 2 selectors = 17pts (3+ selectors = 21pts)")
        elif selector_count >= 3:
            print(f"   Scoring: {selector_count} selectors = 21pts (maximum)")
    else:
        print("   ❌ No DKIM records found (checked common selectors)")
    
    # MTA-STS DISPLAY
    print(f"\n🔒 MTA-STS ({mta_sts_score}/12)")
    if mta_sts_result and mta_sts_result.get('record'):
        print(f"   Record: {mta_sts_result['record']}")
        if mta_sts_result.get('policy'):
            print(f"   Policy: ✅ Accessible")
            if verbose and mta_sts_result.get('policy_content'):
                for line in mta_sts_result['policy_content'].strip().split('\n')[:5]:
                    print(f"      {line}")
        else:
            print(f"   Policy: ❌ Not accessible")
        
        for issue in mta_sts_result.get('issues', []):
            print(f"   ❌ {issue['message']}")
        for warning in mta_sts_result.get('warnings', []):
            print(f"   ⚠️  {warning['message']}")
    else:
        print("   ❌ No MTA-STS record found")
    
    # TLS-RPT DISPLAY
    print(f"\n📊 TLS-RPT ({tlsrpt_score}/12)")
    if tlsrpt_result and tlsrpt_result.get('record'):
        print(f"   Record: {tlsrpt_result['record']}")
        if tlsrpt_result.get('rua'):
            print(f"   Reporting URI: {tlsrpt_result['rua']}")
    else:
        print("   ❌ No TLS-RPT record found")
    
    # BIMI DISPLAY
    print(f"\n🎨 BIMI ({bimi_score}/8)")
    if bimi_result and bimi_result.get('record'):
        print(f"   Record: {bimi_result['record']}")
        print(f"   DMARC Compliant: {'✅' if bimi_result.get('dmarc_compliant') else '❌'}")
        
        if bimi_result.get('logo_check'):
            logo = bimi_result['logo_check']
            print(f"   Logo URL: {logo.get('url', 'N/A')}")
            print(f"   Logo Accessible: {'✅' if logo.get('accessible') else '❌'}")
            print(f"   Logo is SVG: {'✅' if logo.get('is_svg') else '❌'}")
            print(f"   Logo via HTTPS: {'✅' if logo.get('is_secure') else '❌'}")
        
        if bimi_result.get('vmc_check'):
            vmc = bimi_result['vmc_check']
            if vmc.get('found'):
                print(f"   VMC Certificate: ✅ Found")
                if vmc.get('validity'):
                    v = vmc['validity']
                    print(f"   VMC Valid: {'✅' if v.get('is_valid') else '❌'} (expires in {v.get('days_remaining', 0)} days)")
                if vmc.get('issuer'):
                    i = vmc['issuer']
                    print(f"   VMC Issuer: {i.get('issuer', 'Unknown')} ({'✅ Authorized' if i.get('is_authorized') else '❌ Not authorized'})")
                if vmc.get('domain'):
                    d = vmc['domain']
                    print(f"   VMC Domain Match: {'✅' if d.get('domain_match') else '❌'}")
            else:
                print(f"   VMC Certificate: ❌ {vmc.get('error', 'Not found')}")
    else:
        print("   ❌ No BIMI record found")
    
    # =========================================================================
    # RECOMMENDATIONS
    # =========================================================================
    print(f"\n{'─'*60}")
    print("📋 RECOMMENDATIONS:\n")

    #Get categorized recommendations
    recommendations = categorize_recommendations(
        spf_result, dmarc_result, dkim_score,
        mta_sts_result, tlsrpt_result, bimi_result
    )

    #Check if there are any recommendations
    total_recommendations = (
        len(recommendations['critical']) +
        len(recommendations['high']) +
        len(recommendations['medium']) +
        len(recommendations['low'])
    )

    if total_recommendations == 0:
        print("✅ Excellent! Your email security configuration is comprehensive.\n")
    else:
        #Display CRITICAL recommendations
        if recommendations['critical']:
            print(f"🔴 CRITICAL ISSUES ({len(recommendations['critical'])})")
            for rec in recommendations['critical']:
                print(f"  • {rec}")
            print()

        #Display HIGH PRIORITY recommendations
        if recommendations['high']:
            print(f"🟠 HIGH PRIORITY ({len(recommendations['high'])})")
            for rec in recommendations['high']:
                print(f"  • {rec}")
            print()

        #Display MEDIUM PRIORITY recommendations
        if recommendations['medium']:
            print(f"🟡 MEDIUM PRIORITY ({len(recommendations['medium'])})")
            for rec in recommendations['medium']:
                print(f"  • {rec}")
            print()

        #Display LOW PRIORITY recommendations
        if recommendations['low']:
            print(f"🟢 LOW PRIORITY ({len(recommendations['low'])})")
            for rec in recommendations['low']:
                print(f"  • {rec}")
            print()

    print(f"{'='*60}\n")



# MAIN


def main():
    options = prog_parse()
    domain = options.domain
    verbose = options.verbose

    #Configure custom nameserver if provided
    if options.nameserver:
        global DNS_RESOLVER
        try:
            ipaddress.ip_address(options.nameserver)
            DNS_RESOLVER = dns.resolver.Resolver()
            DNS_RESOLVER.nameservers = [options.nameserver]
            print(f"🌐 Using nameserver: {options.nameserver}")
        except ValueError:
            print(f"❌ Error: '{options.nameserver}' is not a valid IP address")
            sys.exit(1)

    custom_selectors = []
    if options.selector:
        selector_input = input("Enter DKIM selector(s) separated by comma: ")
        custom_selectors = [s.strip() for s in selector_input.split(',') if s.strip()]

    print(f"\n🔍 Analyzing domain: {domain}")
    print("   Please wait...")
    
    spf_result = spf_resolver(domain)
    dmarc_result = dmarc_resolver(domain)
    dkim_result = dkim_resolver(domain, custom_selectors if custom_selectors else None)
    mta_sts_result = mta_sts_resolver(domain)
    tlsrpt_result = tlsrpt_resolver(domain)
    bimi_result = bimi_resolver(domain, dmarc_result)
    
    analyze_results(
        domain,
        spf_result,
        dmarc_result,
        dkim_result,
        mta_sts_result,
        tlsrpt_result,
        bimi_result,
        verbose
    )


if __name__ == "__main__":
    main()
