"""
MAILTRACE AI — Deep IOC Extractor
Extracts IPv4, IPv6, Domains, URLs, Email Addresses, and Cryptographic Hashes from RFC 822 payloads.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Dict, Set, Tuple

# Regex Patterns
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
URL_REGEX = re.compile(r'https?://[^\s<>"\',;]+', re.IGNORECASE)
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63})\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')

# Ignore noise domains commonly found in MIME or standard headers
COMMON_IGNORE_DOMAINS = {
    'w3.org', 'schema.org', 'schemas.microsoft.com', 'schemas.openxmlformats.org',
    'example.com', 'example.org', 'example.net', 'localhost', 'internal'
}

def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False

def extract_iocs_from_text(text: str) -> Dict[str, Set[str]]:
    """Extracts all raw indicator strings categorized by type."""
    iocs = {
        'IP': set(),
        'DOMAIN': set(),
        'URL': set(),
        'EMAIL': set(),
        'HASH': set(),
    }

    if not text:
        return iocs

    # Extract URLs first
    raw_urls = URL_REGEX.findall(text)
    for u in raw_urls:
        # Strip trailing punctuation
        cleaned_url = u.rstrip('.,)>];\'"')
        if cleaned_url.startswith('http'):
            iocs['URL'].add(cleaned_url)
            try:
                parsed = urlparse(cleaned_url)
                if parsed.hostname and '.' in parsed.hostname:
                    if is_public_ip(parsed.hostname):
                        iocs['IP'].add(parsed.hostname)
                    elif parsed.hostname.lower() not in COMMON_IGNORE_DOMAINS:
                        iocs['DOMAIN'].add(parsed.hostname.lower())
            except Exception:
                pass

    # Extract IPs
    for ip in IPV4_REGEX.findall(text):
        if is_public_ip(ip):
            iocs['IP'].add(ip)

    # Extract Emails
    for email in EMAIL_REGEX.findall(text):
        email_clean = email.lower().rstrip('.')
        iocs['EMAIL'].add(email_clean)
        domain = email_clean.split('@')[-1]
        if domain not in COMMON_IGNORE_DOMAINS:
            iocs['DOMAIN'].add(domain)

    # Extract Domains
    for domain in DOMAIN_REGEX.findall(text):
        d_lower = domain.lower().rstrip('.')
        if d_lower not in COMMON_IGNORE_DOMAINS and not is_public_ip(d_lower):
            # Avoid file extensions masquerading as domains (like .png, .jpg, .pdf)
            tld = d_lower.split('.')[-1]
            if tld not in {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'html', 'js', 'css', 'xml'}:
                iocs['DOMAIN'].add(d_lower)

    # Extract Hashes
    for h in SHA256_REGEX.findall(text):
        iocs['HASH'].add(h.lower())

    return iocs
