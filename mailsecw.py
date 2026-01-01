# Author: Enzo LE NAIR
# Version: V0.0.2 
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

if __name__ == "__main__":
    options = prog_parse()
    domain = options.domain
    print(domain)
    spf  = spf_resolver(domain)
    print(dmarc_resolver(domain))


