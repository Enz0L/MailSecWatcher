# Author: Enzo LE NAIR
# Version: V1.3.9
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

def prog_parse():
    parser = ArgumentParser(
        prog=__file__,
        description="Analyze SPF, DMARC, DKIM, TLS-RPT, MTA-STS & BIMI",
        usage="%(prog)s [options] -d domaine_name"
    )
    parser.add_argument("-d", "--domain", help="Specify domain name", required=True)
    parser.add_argument("-s", "--selector", action="store_true", help="Prompt for custom DKIM selector(s)")
    options = parser.parse_args()
    return options

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
            return spf, spf_meca
        return None, None
    except Exception:
        return None, None

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

def dkim_resolver(domain, custom_selector=False):
    results = []

    default_selectors = [
        "selector1", "selector2", "google", "k1", "k2", "ctct1", "ctct2", "sm", "s1", "s2",
        "sig1", "litesrv", "zendesk1", "zendesk2", "mail", "email", "dkim", "default", "class",
        "spop", "spop1024", "bfi", "alpha", "authsmtp", "pmta", "m", "main", "stigmate",
        "squaremail", "publickey", "proddkim", "ED-DKIM", "care", "0xdeadbeef", "yousendit",
        "scooby", "postfix.private", "primary", "mandrill", "dkimmail", "protonmail",
        "protonmail2", "protonmail3"
    ]

    if custom_selector:
        print("\n🔑 DKIM Custom Selector Mode")
        print("-" * 30)
        print("Enter selector(s) to test (comma-separated for multiple)")
        print("Example: myselector1, myselector2")
        user_input = input("Selector(s): ").strip()
        if user_input:
            custom_selectors = [s.strip() for s in user_input.split(",") if s.strip()]
            selectors = custom_selectors + default_selectors
        else:
            selectors = default_selectors
    else:
        selectors = default_selectors

    tested_selectors = set()

    for selector in selectors:
        if selector in tested_selectors:
            continue
        tested_selectors.add(selector)

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

def mta_sts_resolver(domain):
    result = {
        "dns_record": None,
        "policy": None,
        "mode": None,
        "mx": [],
        "max_age": None
    }
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
        response = requests.get(policy_url, timeout=10)
        if response.status_code == 200:
            result["policy"] = response.text
            lines = response.text.strip().split('\n')
            for line in lines:
                if line.startswith("mode:"):
                    result["mode"] = line.split(":")[1].strip()
                elif line.startswith("mx:"):
                    result["mx"].append(line.split(":")[1].strip())
                elif line.startswith("max_age:"):
                    result["max_age"] = line.split(":")[1].strip()
    except Exception:
        pass
    return result

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
    try:
        eku_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        eku_oids = [oid.dotted_string for oid in eku_ext.value]
        has_bimi_eku = BIMI_EKU_OID in eku_oids
        return {
            "found": True,
            "eku_oids": eku_oids,
            "has_bimi_eku": has_bimi_eku
        }
    except x509.ExtensionNotFound:
        return {
            "found": False,
            "eku_oids": [],
            "has_bimi_eku": False
        }

def verify_vmc_logo_extension(certificate):
    LOGOTYPE_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.12")
    try:
        for ext in certificate.extensions:
            if ext.oid == LOGOTYPE_OID:
                return {
                    "found": True,
                    "has_embedded_logo": True
                }
        return {
            "found": False,
            "has_embedded_logo": False
        }
    except Exception:
        return {
            "found": False,
            "has_embedded_logo": False
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

def check_dmarc_compliance(dmarc_record):
    if not dmarc_record:
        return False
    dmarc_lower = dmarc_record.lower()
    if "p=reject" in dmarc_lower or "p=quarantine" in dmarc_lower:
        return True
    return False

def verify_vmc(vmc_url, domain):
    vmc_result = {
        "found": False,
        "url": vmc_url,
        "error": None,
        "validity": None,
        "issuer": None,
        "domain": None,
        "eku": None,
        "logo_extension": None,
        "score": 0
    }
    certificate, error = fetch_vmc_certificate(vmc_url)
    if error:
        vmc_result["error"] = error
        return vmc_result
    vmc_result["found"] = True
    vmc_result["validity"] = verify_vmc_validity(certificate)
    vmc_result["issuer"] = verify_vmc_issuer(certificate)
    vmc_result["domain"] = verify_vmc_domain(certificate, domain)
    vmc_result["eku"] = verify_vmc_eku(certificate)
    vmc_result["logo_extension"] = verify_vmc_logo_extension(certificate)
    score = 0
    if vmc_result["validity"]["is_valid"]:
        score += 2
    if vmc_result["issuer"]["is_authorized"]:
        score += 2
    if vmc_result["domain"]["domain_match"]:
        score += 1
    if vmc_result["eku"]["has_bimi_eku"]:
        score += 1
    if vmc_result["logo_extension"]["has_embedded_logo"]:
        score += 1
    vmc_result["score"] = score
    return vmc_result

def bimi_resolver(domain, dmarc_record):
    result = {
        "record": None,
        "logo_url": None,
        "vmc_url": None,
        "dmarc_compliant": False,
        "logo_check": None,
        "vmc_check": None
    }
    result["dmarc_compliant"] = check_dmarc_compliance(dmarc_record)
    try:
        bimi_domain = f"default._bimi.{domain}"
        answers = dns.resolver.resolve(bimi_domain, 'TXT')
        for answer in answers:
            record = answer.to_text().strip('"')
            if "v=BIMI1" in record:
                result["record"] = record
                if "l=" in record:
                    parts = record.split(";")
                    for part in parts:
                        part = part.strip()
                        if part.startswith("l="):
                            result["logo_url"] = part[2:].strip()
                        elif part.startswith("a="):
                            result["vmc_url"] = part[2:].strip()
                break
    except Exception:
        pass
    if result["logo_url"]:
        result["logo_check"] = verify_logo_url(result["logo_url"])
    if result["vmc_url"]:
        result["vmc_check"] = verify_vmc(result["vmc_url"], domain)
    return result

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
    
    return result

def calculate_spf_score(spf_result):
    spf_record, spf_mechanism = spf_result
    if not spf_record:
        return 0
    score = 5
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

def calculate_dmarc_score(dmarc_record):
    if not dmarc_record:
        return 0
    
    parsed = parse_dmarc_tags(dmarc_record)
    explicit = parsed.get("explicit", {})
    effective = parsed.get("effective", {})
    
    score = 5  # Base score for having DMARC
    
    # Policy scoring (using effective value)
    p = effective.get("p", "none")
    if p == "reject":
        score += 10
    elif p == "quarantine":
        score += 7
    elif p == "none":
        score += 2
    
    # Subdomain policy scoring
    sp = effective.get("sp", p)
    sp_explicit = "sp" in explicit
    if sp == "reject":
        score += 4 if sp_explicit else 3  # Bonus for explicit
    elif sp == "quarantine":
        score += 3 if sp_explicit else 2
    elif sp == "none":
        score += 0
    
    # Reporting
    if "rua" in explicit:
        score += 4
    if "ruf" in explicit:
        score += 2
    
    # Alignment (strict = bonus, relaxed is default and acceptable)
    adkim = effective.get("adkim", "r")
    aspf = effective.get("aspf", "r")
    
    if adkim == "s":
        score += 1
    # No penalty for relaxed (default)
    
    if aspf == "s":
        score += 1
    # No penalty for relaxed (default)
    
    return min(score, 27)

def calculate_dkim_score(dkim_result):
    if dkim_result:
        return 21
    return 0

def calculate_mta_sts_score(mta_sts_result):
    score = 0
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
    return min(score, 14)

def calculate_tlsrpt_score(tlsrpt_result):
    score = 0
    if tlsrpt_result["record"]:
        score += 5
        if tlsrpt_result["rua"]:
            score += 5
    return min(score, 10)

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

def analyze_results(domain, spf_result, dmarc_result, dkim_result, mta_sts_result, tlsrpt_result, bimi_result):
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

    print(f"📧 SPF ({spf_score}/20)")
    if spf_result[0]:
        print(f"   Record: {spf_result[0]}")
        print(f"   Mechanism: {spf_result[1]}")
    else:
        print("   ❌ No SPF record found")

    print(f"\n📧 DMARC ({dmarc_score}/27)")
    if dmarc_result:
        print(f"   Record: {dmarc_result}")
        if dmarc_parsed:
            explicit = dmarc_parsed.get("explicit", {})
            effective = dmarc_parsed.get("effective", {})
            
            # Show effective values with indication if default
            p_val = effective.get("p", "none")
            print(f"   Policy (p): {p_val}")
            
            sp_val = effective.get("sp", p_val)
            sp_source = "explicit" if "sp" in explicit else f"inherited from p={p_val}"
            print(f"   Subdomain Policy (sp): {sp_val} ({sp_source})")
            
            adkim_val = effective.get("adkim", "r")
            adkim_source = "explicit" if "adkim" in explicit else "default"
            print(f"   DKIM Alignment (adkim): {adkim_val} ({adkim_source})")
            
            aspf_val = effective.get("aspf", "r")
            aspf_source = "explicit" if "aspf" in explicit else "default"
            print(f"   SPF Alignment (aspf): {aspf_val} ({aspf_source})")
            
            if "rua" in explicit:
                print(f"   Aggregate Reports (rua): ✅ configured")
            else:
                print(f"   Aggregate Reports (rua): ❌ not configured")
            
            if "ruf" in explicit:
                print(f"   Forensic Reports (ruf): ✅ configured")
            else:
                print(f"   Forensic Reports (ruf): ❌ not configured")
    else:
        print("   ❌ No DMARC record found")

    print(f"\n📧 DKIM ({dkim_score}/21)")
    if dkim_result:
        for entry in dkim_result:
            print(f"   ✅ Selector: {entry['selector']} ({entry['type']})")
    else:
        print("   ❌ No DKIM selectors found")

    print(f"\n🔒 MTA-STS ({mta_sts_score}/14)")
    if mta_sts_result["dns_record"]:
        print(f"   DNS: {mta_sts_result['dns_record']}")
        if mta_sts_result["mode"]:
            print(f"   Mode: {mta_sts_result['mode']}")
        if mta_sts_result["mx"]:
            print(f"   MX: {', '.join(mta_sts_result['mx'])}")
    else:
        print("   ❌ No MTA-STS record found")

    print(f"\n📊 TLS-RPT ({tlsrpt_score}/10)")
    if tlsrpt_result["record"]:
        print(f"   Record: {tlsrpt_result['record']}")
        if tlsrpt_result["rua"]:
            print(f"   Report URI: {tlsrpt_result['rua']}")
    else:
        print("   ❌ No TLS-RPT record found")

    print(f"\n🎨 BIMI ({bimi_score}/8)")
    if bimi_result["record"]:
        print(f"   Record: {bimi_result['record']}")
        print(f"   DMARC Compliant: {'✅ Yes' if bimi_result['dmarc_compliant'] else '❌ No'}")
        if bimi_result["logo_check"]:
            logo = bimi_result["logo_check"]
            status = "✅" if logo["accessible"] and logo["is_svg"] else "❌"
            print(f"   Logo: {status} {logo['url']}")
            if logo["accessible"]:
                print(f"      Type: {'SVG ✅' if logo['is_svg'] else 'Not SVG ❌'}")
                print(f"      Secure: {'HTTPS ✅' if logo['is_secure'] else 'HTTP ❌'}")
                print(f"      Size: {logo['size_bytes']} bytes")
        if bimi_result["vmc_check"]:
            vmc = bimi_result["vmc_check"]
            if vmc["found"]:
                print(f"   VMC Certificate:")
                if vmc["validity"]:
                    validity_status = "✅ Valid" if vmc["validity"]["is_valid"] else "❌ Invalid"
                    print(f"      Validity: {validity_status}")
                    if vmc["validity"]["is_valid"]:
                        print(f"      Expires: {vmc['validity']['not_after']} ({vmc['validity']['days_remaining']} days)")
                if vmc["issuer"]:
                    issuer_status = "✅" if vmc["issuer"]["is_authorized"] else "❌"
                    print(f"      Issuer: {issuer_status} {vmc['issuer']['ca_name']}")
                if vmc["domain"]:
                    domain_status = "✅" if vmc["domain"]["domain_match"] else "❌"
                    print(f"      Domain Match: {domain_status}")
                if vmc["eku"]:
                    eku_status = "✅" if vmc["eku"]["has_bimi_eku"] else "❌"
                    print(f"      BIMI EKU: {eku_status}")
                if vmc["logo_extension"]:
                    logo_ext_status = "✅" if vmc["logo_extension"]["has_embedded_logo"] else "❌"
                    print(f"      Embedded Logo: {logo_ext_status}")
            else:
                print(f"   VMC: ❌ Error - {vmc.get('error', 'Unknown error')}")
    else:
        print("   ❌ No BIMI record found")

    print(f"\n{'='*60}")
    print(f"  TOTAL SCORE: {total_score}/100 - Grade: {emoji} {grade}")
    print(f"{'='*60}")

    print(f"\n📊 Score Breakdown:")
    print(f"   SPF:     {spf_score:2}/20  {'█' * (spf_score * 12 // 20)}{'░' * (12 - spf_score * 12 // 20)}")
    print(f"   DMARC:   {dmarc_score:2}/27  {'█' * (dmarc_score * 12 // 27)}{'░' * (12 - dmarc_score * 12 // 27)}")
    print(f"   DKIM:    {dkim_score:2}/21  {'█' * (dkim_score * 12 // 21)}{'░' * (12 - dkim_score * 12 // 21)}")
    print(f"   MTA-STS: {mta_sts_score:2}/14  {'█' * (mta_sts_score * 12 // 14)}{'░' * (12 - mta_sts_score * 12 // 14)}")
    print(f"   TLS-RPT: {tlsrpt_score:2}/10  {'█' * (tlsrpt_score * 12 // 10)}{'░' * (12 - tlsrpt_score * 12 // 10)}")
    print(f"   BIMI:    {bimi_score:2}/8   {'█' * (bimi_score * 12 // 8)}{'░' * (12 - bimi_score * 12 // 8)}")

    print(f"\n💡 Recommendations:")
    actions = []

    # SPF recommendations
    if spf_score < 20:
        if spf_score == 0:
            actions.append("• Implement SPF record (v=spf1 ... -all)")
        elif spf_result[1] == "softfail":
            actions.append("• Harden SPF: change '~all' to '-all' (hardfail)")
        elif spf_result[1] == "neutral":
            actions.append("• Harden SPF: change '?all' to '-all' (hardfail)")
        elif spf_result[1] == "pass":
            actions.append("• CRITICAL: Remove '+all' from SPF (allows anyone to spoof)")

    # DMARC recommendations
    if dmarc_score < 27:
        if dmarc_score == 0:
            actions.append("• Implement DMARC record (v=DMARC1; p=reject; rua=mailto:...)")
        else:
            parsed = parse_dmarc_tags(dmarc_result)
            explicit = parsed.get("explicit", {})
            effective = parsed.get("effective", {})
            
            # Policy recommendations
            p = effective.get("p", "none")
            if p == "none":
                actions.append("• Upgrade DMARC policy from 'none' to 'quarantine' or 'reject'")
            elif p == "quarantine":
                actions.append("• Consider upgrading DMARC policy from 'quarantine' to 'reject'")
            
            # Subdomain policy
            sp = effective.get("sp", p)
            if "sp" not in explicit:
                if p != "reject":
                    actions.append("• Consider adding explicit subdomain policy (sp=reject)")
            elif sp == "none":
                actions.append("• Upgrade subdomain policy from 'none' to 'reject'")
            elif sp == "quarantine":
                actions.append("• Consider upgrading subdomain policy from 'quarantine' to 'reject'")
            
            # Reporting
            if "rua" not in explicit:
                actions.append("• Add DMARC aggregate reporting (rua=mailto:...)")
            if "ruf" not in explicit:
                actions.append("• Consider adding DMARC forensic reporting (ruf=)")
            
            # Alignment (optional enhancements)
            adkim = effective.get("adkim", "r")
            aspf = effective.get("aspf", "r")
            
            if adkim != "s":
                actions.append("• Consider strict DKIM alignment (adkim=s) for enhanced security")
            if aspf != "s":
                actions.append("• Consider strict SPF alignment (aspf=s) for enhanced security")

    # DKIM recommendations
    if dkim_score == 0:
        actions.append("• Implement DKIM signing for outgoing emails")

    # MTA-STS recommendations
    if mta_sts_score < 14:
        if mta_sts_score == 0:
            actions.append("• Implement MTA-STS (DNS record + policy file)")
        else:
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

if __name__ == "__main__":
    options = prog_parse()
    domain = options.domain
    print(f"Analyzing domain: {domain}")

    spf_result = spf_resolver(domain)
    dmarc_result = dmarc_resolver(domain)
    dkim_result = dkim_resolver(domain, options.selector)
    mta_sts_result = mta_sts_resolver(domain)
    tlsrpt_result = tlsrpt_resolver(domain)
    bimi_result = bimi_resolver(domain, dmarc_result)

    analyze_results(domain, spf_result, dmarc_result, dkim_result, mta_sts_result, tlsrpt_result, bimi_result)
