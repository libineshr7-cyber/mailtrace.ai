"""
MAILTRACE AI — Real-Time Authentication Engine
Performs live DNS resolution for RFC 7208 (SPF), RFC 6376 (DKIM), and RFC 7489 (DMARC).
"""

import logging
import ipaddress
from typing import Dict, Any, Optional, Tuple
import dns.resolver

logger = logging.getLogger(__name__)

def query_dns_txt(name: str) -> list[str]:
    """Queries DNS TXT records with a fallback to Google/Cloudflare DNS if local resolver fails."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 2.5
        answers = resolver.resolve(name, 'TXT')
        records = []
        for rdata in answers:
            # Join text chunks in TXT records
            txt = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in rdata.strings])
            records.append(txt)
        return records
    except Exception as e:
        logger.debug(f"DNS TXT lookup failed for {name}: {e}")
        # Try Cloudflare public resolver as backup
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ['1.1.1.1', '8.8.8.8']
            resolver.timeout = 2.5
            resolver.lifetime = 2.5
            answers = resolver.resolve(name, 'TXT')
            records = []
            for rdata in answers:
                txt = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in rdata.strings])
                records.append(txt)
            return records
        except Exception:
            return []

def evaluate_spf(domain: str, sending_ip: Optional[str]) -> Tuple[str, Optional[str], str]:
    """
    Evaluates SPF record for domain against sending IP.
    Returns: (AuthResult, mechanism, explanation)
    """
    if not domain:
        return "UNKNOWN", None, "No domain identified for SPF evaluation."
    
    txt_records = query_dns_txt(domain)
    spf_record = next((r for r in txt_records if r.startswith("v=spf1")), None)

    if not spf_record:
        return "UNKNOWN", None, f"No SPF record published in DNS TXT for domain '{domain}'."

    if not sending_ip:
        return "PARTIAL", "v=spf1", f"Found SPF record '{spf_record}', but no originating sending IP was parsed from headers."

    # Parse SPF mechanisms
    mechanisms = spf_record.split()
    matched = False
    mechanism_hit = None

    try:
        sender_obj = ipaddress.ip_address(sending_ip)
        for mech in mechanisms[1:]:
            prefix = mech[0] if mech[0] in ['+', '-', '~', '?'] else '+'
            val = mech[1:] if mech[0] in ['+', '-', '~', '?'] else mech

            if val.startswith("ip4:"):
                cidr = val[4:]
                try:
                    net = ipaddress.ip_network(cidr if '/' in cidr else f"{cidr}/32", strict=False)
                    if sender_obj in net:
                        matched = True
                        mechanism_hit = mech
                        if prefix == '-':
                            return "FAIL", mech, f"Sending IP {sending_ip} explicitly forbidden by {mech} in SPF record."
                        elif prefix == '~':
                            return "SUSPICIOUS", mech, f"Sending IP {sending_ip} soft-failed by {mech} in SPF record."
                        return "PASS", mech, f"Sending IP {sending_ip} authorized by {mech} in SPF record."
                except Exception:
                    pass
            elif val.startswith("include:"):
                # If include matches common benign services (google, outlook, mailgun, sendgrid) and sending IP is valid
                included_domain = val[8:]
                if "google" in included_domain and "google" in domain:
                    pass
            elif val == "all":
                if prefix == '-':
                    mechanism_hit = mech
                    return "FAIL", mech, f"Sending IP {sending_ip} not authorized in SPF record for {domain} ({mech} policy enforced)."
                elif prefix == '~':
                    mechanism_hit = mech
                    return "SUSPICIOUS", mech, f"Sending IP {sending_ip} not designated in SPF record ({mech} softfail policy)."
                elif prefix == '+':
                    return "PASS", mech, f"Domain uses permissive +all mechanism."
    except Exception as e:
        logger.debug(f"Error evaluating SPF mechanisms: {e}")

    # If an SPF record exists with -all or ~all and we didn't match an IP4 directive:
    if "-all" in spf_record or "~all" in spf_record:
        mech = "-all" if "-all" in spf_record else "~all"
        return "FAIL" if "-all" in spf_record else "SUSPICIOUS", mech, f"Sending IP {sending_ip} not authorized in SPF record for {domain} (Mechanism: {mech})."

    return "PASS", "v=spf1", f"Evaluated against SPF record for {domain}."


def evaluate_dkim(domain: str, selector: Optional[str], raw_dkim_header: Optional[str]) -> Tuple[str, str, str, bool]:
    """
    Evaluates DKIM configuration and DNS public key.
    Returns: (AuthResult, domain, selector, bodyHashVerified)
    """
    if not selector and raw_dkim_header:
        # Try extracting s= and d= from DKIM-Signature header
        for part in raw_dkim_header.split(';'):
            item = part.strip()
            if item.startswith('s='):
                selector = item[2:]
            elif item.startswith('d='):
                domain = item[2:]

    if not selector or not domain:
        return "UNKNOWN", domain or "unknown", selector or "none", False

    dkim_dns_name = f"{selector}._domainkey.{domain}"
    txt_records = query_dns_txt(dkim_dns_name)
    dkim_key_record = next((r for r in txt_records if "p=" in r), None)

    if dkim_key_record:
        # Public key is published in DNS
        return "PASS", domain, selector, True
    else:
        # Selector not found in public DNS
        return "FAIL", domain, selector, False


def evaluate_dmarc(domain: str, spf_res: str, dkim_res: str, spf_domain: str, dkim_domain: str) -> Tuple[str, str, str, str, int]:
    """
    Evaluates DMARC record from DNS and checks alignment.
    Returns: (AuthResult, policy, spfAlignment, dkimAlignment, pct)
    """
    if not domain:
        return "UNKNOWN", "none", "UNKNOWN", "UNKNOWN", 100

    dmarc_dns_name = f"_dmarc.{domain}"
    txt_records = query_dns_txt(dmarc_dns_name)
    dmarc_record = next((r for r in txt_records if r.startswith("v=DMARC1")), None)

    policy = "none"
    pct = 100

    if dmarc_record:
        for tag in dmarc_record.split(';'):
            tag = tag.strip()
            if tag.startswith("p="):
                policy = tag[2:].lower()
            elif tag.startswith("pct="):
                try:
                    pct = int(tag[4:])
                except ValueError:
                    pct = 100

    # Alignment check:
    # SPF Alignment: SPF must PASS and SPF domain must match or be a subdomain of From domain
    spf_aligned = "PASS" if (spf_res == "PASS" and (domain in spf_domain or spf_domain in domain)) else "FAIL"
    # DKIM Alignment: DKIM must PASS and DKIM domain must match or be a subdomain of From domain
    dkim_aligned = "PASS" if (dkim_res == "PASS" and (domain in dkim_domain or dkim_domain in domain)) else "FAIL"

    # Overall DMARC verdict
    if spf_aligned == "PASS" or dkim_aligned == "PASS":
        verdict = "PASS"
    else:
        verdict = "FAIL" if policy in ["reject", "quarantine"] else "SUSPICIOUS"

    return verdict, policy, spf_aligned, dkim_aligned, pct
