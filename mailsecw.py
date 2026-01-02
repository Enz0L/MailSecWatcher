# Author: Enzo LE NAIR
# Version: V0.0.4 
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
def prog_parse():
    parser = ArgumentParser(prog=__file__, description= "Analyze SPF,DMARC,DKIM, TLS-RPT & MTA-STS ", usage = "%(prog)s [options] -d domaine_name")
    parser.add_argument("-d", "--domain",help="Specify domain name",required=True)
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
        answers = dns.resolver.resolve(domain,'TXT')
        for answer in answers:
            if "v=spf1" in answer.to_text():
                spf = answer.to_text()
        spf_meca = next((meca for pattern, meca in mechanism.items() if pattern in spf), "unknown")

        return spf, spf_meca
    except:
        print("Cant find SPF in TXT records")

def dmarc_resolver(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for answer in answers:
            dmarc = answer
        return dmarc
    except:
        print("Can't resolve DMARC")


def dkim_resolver(domain, selectors_provided):
    results = []  

    if selectors_provided:
        selector = input("Give a selector to test: ")
        try:
            answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "CNAME")
            results = [answer.to_text() for answer in answers]
        except:
            pass  

    else:
        selectors = [
            "selector1", "selector2", "google", "k1", "k2", "ctct1", "ctct2", "sm", "s1", "s2",
            "sig1", "litesrv", "zendesk1", "zendesk2", "mail", "email", "dkim", "default", "class",
            "spop", "spop1024", "bfi", "alpha", "authsmtp", "pmta", "m", "main", "stigmate",
            "squaremail", "publickey", "proddkim", "ED-DKIM", "care", "0xdeadbeef", "yousendit",
            "scooby", "postfix.private", "primary", "mandrill", "dkimmail", "protonmail",
            "protonmail2", "protonmail3"
        ]

        for selector in selectors:
            try:
                answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "CNAME")
                for answer in answers:
                    results.append(f"{selector}: {answer.to_text()}")
            except:
                continue  
    return results if results else ["No DKIM Record"]


def analyze_results(domain, spf_result, dmarc_result, dkim_result):
    """
    Analyze SPF, DMARC, and DKIM results and provide security assessment.
    """
    print(f"\n{'='*60}")
    print(f"SECURITY ANALYSIS FOR DOMAIN: {domain.upper()}")
    print(f"{'='*60}")
    
    print("\n🔍 SPF ANALYSIS:")
    print("-" * 20)
    if isinstance(spf_result, tuple) and len(spf_result) == 2:
        spf_record, spf_mech = spf_result
        print(f"  SPF Record: {spf_record}")
        print(f"  Fail Mechanism: **{spf_mech.upper()}**")
        
        status = "✅ PASS" if spf_mech == "pass" else "❌ FAIL"
        recommendation = ""
        if spf_mech == "hardfail":
            recommendation = "Good: Strict SPF enforcement"
        elif spf_mech == "softfail":
            recommendation = "Acceptable: Soft enforcement"
        elif spf_mech == "neutral":
            recommendation = "⚠️  Weak: Consider ~all or -all"
        elif spf_mech == "unknown":
            recommendation = "❌ MISSING: No SPF record found"
            
        print(f"  Status: {status}")
        print(f"  Recommendation: {recommendation}")
    else:
        print("  ❌ No SPF record found or error resolving")
    
    print("\n🔍 DMARC ANALYSIS:")
    print("-" * 20)
    if dmarc_result and not isinstance(dmarc_result, str) or "v=DMARC" in str(dmarc_result):
        dmarc_str = str(dmarc_result).strip('"') if dmarc_result else "Unknown"
        print(f"  DMARC Record: {dmarc_str}")
        
        pct_match = "pct=" in dmarc_str
        rua_match = "rua=" in dmarc_str
        ruf_match = "ruf=" in dmarc_str
        
        print(f"  Aggregate Reports (rua): {'✅ YES' if rua_match else '❌ NO'}")
        print(f"  Forensic Reports (ruf): {'✅ YES' if ruf_match else '❌ NO'}")
        print(f"  Percentage Coverage: {'✅ CONFIGURED' if pct_match else '⚠️ DEFAULT (100%)'}")
        print("  Status: ✅ DMARC IMPLEMENTED")
    else:
        print("  ❌ No DMARC record found")
        print("  Recommendation: Implement DMARC immediately!")
    
    print("\n🔍 DKIM ANALYSIS:")
    print("-" * 20)
    if isinstance(dkim_result, list):
        if dkim_result == ["No DKIM Record"]:
            print("  ❌ No DKIM selectors found")
            print("  Recommendation: Add DKIM selectors (default, google, s1, s2, etc.)")
        else:
            print(f"  Found **{len(dkim_result)}** DKIM selector(s):")
            for result in dkim_result[:5]:  # Show first 5
                print(f"    • {result}")
            if len(dkim_result) > 5:
                print(f"    ... and {len(dkim_result) - 5} more")
            print("  Status: ✅ DKIM SELECTORS FOUND")
    else:
        print("  ⚠️  DKIM result format unexpected")
    
    print("\n📊 OVERALL SECURITY SCORE:")
    print("-" * 20)
    score = 0
    status_emoji = "🟢"
    
    if isinstance(spf_result, tuple) and spf_result[1] in ["pass", "hardfail", "softfail"]:
        score += 30
    if dmarc_result and "v=DMARC" in str(dmarc_result):
        score += 40
    if isinstance(dkim_result, list) and dkim_result != ["No DKIM Record"] and dkim_result:
        score += 30
    
    if score >= 90:
        status_emoji = "🟢 EXCELLENT"
    elif score >= 70:
        status_emoji = "🟡 GOOD"
    elif score >= 40:
        status_emoji = "🟠 FAIR"
    else:
        status_emoji = "🔴 POOR"
    
    print(f"  Score: {score}/100 {status_emoji}")
    print(f"  Coverage: SPF:{'25%' if score >= 25 else '0%'} DMARC:{'40%' if score >= 65 else '0%'} DKIM:{'35%' if score >= 95 else '0%'}")
    
    # Action Items
    print("\n✅ ACTION ITEMS:")
    print("-" * 20)
    if not (isinstance(spf_result, tuple) and spf_result[1] in ["pass", "hardfail"]):
        print("  • Upgrade SPF to -all (hardfail)")
    if not (dmarc_result and "v=DMARC" in str(dmarc_result)):
        print("  • Implement DMARC with rua=mailto:reports@yourdomain.com")
    if dkim_result == ["No DKIM Record"]:
        print("  • Add DKIM selectors (s1._domainkey, s2._domainkey, etc.)")
    
    print(f"{'='*60}\n")

if __name__ == "__main__":
    options = prog_parse()
    domain = options.domain
    print(f"Analyzing domain: {domain}")
    
    spf_result = spf_resolver(domain)
    dmarc_result = dmarc_resolver(domain) 
    dkim_result = dkim_resolver(domain, False)
    
    # NEW: Analyze all results together
    analyze_results(domain, spf_result, dmarc_result, dkim_result)