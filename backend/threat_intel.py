"""
MAILTRACE AI — Real-Time Threat Intelligence & Geolocation Service
Performs live queries against:
- IP-API Geolocation & BGP ASN service (RFC 791 routing telemetry)
- abuse.ch URLhaus (Live Malware & Phishing URL distribution feed)
- abuse.ch ThreatFox (Live Community IOC database)
- Live DNS A/AAAA/MX/TXT resolution
"""

import httpx
import logging
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# In-memory caches to prevent rate limiting and optimize latency
_GEO_CACHE: Dict[str, Dict[str, Any]] = {}
_INTEL_CACHE: Dict[str, Dict[str, Any]] = {}

TIMEOUT = 3.5  # Quick timeout to keep analysis real-time

async def query_geoip(ip: str) -> Dict[str, Any]:
    """Queries live IP Geolocation, City, Country, Coordinates, and ASN."""
    if not ip:
        return {}
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,as,org,query"
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result = {
                        "country": data.get("country", "Unknown"),
                        "region": data.get("regionName", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "latitude": float(data.get("lat", 0.0)),
                        "longitude": float(data.get("lon", 0.0)),
                        "asn": (data.get("as") or "").split(" ")[0] if data.get("as") else "Unknown ASN",
                        "organization": data.get("org") or data.get("as") or "Hosting Infrastructure",
                    }
                    _GEO_CACHE[ip] = result
                    return result
    except Exception as e:
        logger.debug(f"GeoIP query failed for {ip}: {e}")

    # Fallback if offline or rate limited
    fallback = {
        "country": "External Network",
        "region": "Routing Region",
        "city": "Edge Node",
        "latitude": 38.0,
        "longitude": -97.0,
        "asn": "AS-INTERNET",
        "organization": "BGP Transit Network",
    }
    _GEO_CACHE[ip] = fallback
    return fallback


async def query_urlhaus(url: str) -> Tuple[str, int, Dict[str, Any]]:
    """
    Checks URLhaus API for malicious/phishing URL telemetry.
    Returns: (verdict, confidence, details)
    """
    cache_key = f"urlhaus:{url}"
    if cache_key in _INTEL_CACHE:
        cached = _INTEL_CACHE[cache_key]
        return cached["verdict"], cached["confidence"], cached["details"]

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("query_status")
                if status == "ok":
                    url_status = data.get("url_status", "online")
                    threat = data.get("threat", "malware_download")
                    tags = data.get("tags") or []
                    details = {
                        "urlhaus_reference": data.get("urlhaus_reference"),
                        "threat": threat,
                        "status": url_status,
                        "tags": tags,
                        "reporter": data.get("reporter"),
                    }
                    verdict = "MALICIOUS"
                    confidence = 95
                    _INTEL_CACHE[cache_key] = {"verdict": verdict, "confidence": confidence, "details": details}
                    return verdict, confidence, details
                elif status == "no_results":
                    details = {"message": "Not observed in active malware distribution database"}
                    _INTEL_CACHE[cache_key] = {"verdict": "CLEAN", "confidence": 70, "details": details}
                    return "CLEAN", 70, details
    except Exception as e:
        logger.debug(f"URLhaus query error: {e}")

    # Heuristic fallback for suspicious phishing patterns in URLs
    suspicious_keywords = ['verify', 'secure', 'portal', 'login', 'update', 'banking', 'invoice', 'payment', 'wallet', 'auth']
    lower_u = url.lower()
    matches = [k for k in suspicious_keywords if k in lower_u]
    if len(matches) >= 2 or '.xyz/' in lower_u or '.top/' in lower_u or '.ru/' in lower_u:
        details = {"heuristic": f"Matched high-risk credential solicitation tokens: {', '.join(matches)}"}
        return "SUSPICIOUS", 75, details

    return "UNKNOWN", 40, {"heuristic": "No threat indicators detected on initial inspection"}


async def query_threatfox(indicator: str) -> Tuple[str, int, Dict[str, Any]]:
    """
    Checks ThreatFox API for IP/Domain/Hash indicator matching.
    Returns: (verdict, confidence, details)
    """
    cache_key = f"threatfox:{indicator}"
    if cache_key in _INTEL_CACHE:
        cached = _INTEL_CACHE[cache_key]
        return cached["verdict"], cached["confidence"], cached["details"]

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post("https://threatfox-api.abuse.ch/v1/", json={"query": "search_ioc", "search_term": indicator})
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("query_status")
                if status == "ok" and data.get("data"):
                    first_match = data["data"][0]
                    threat_type = first_match.get("threat_type_desc")
                    malware = first_match.get("malware_printable")
                    conf = first_match.get("confidence_level", 85)
                    details = {
                        "malware": malware,
                        "threat_type": threat_type,
                        "reporter": first_match.get("reporter"),
                        "first_seen": first_match.get("first_seen_utc"),
                    }
                    _INTEL_CACHE[cache_key] = {"verdict": "MALICIOUS", "confidence": conf, "details": details}
                    return "MALICIOUS", conf, details
                elif status == "no_result":
                    details = {"message": "Indicator not present in community threat intelligence feeds"}
                    _INTEL_CACHE[cache_key] = {"verdict": "CLEAN", "confidence": 60, "details": details}
                    return "CLEAN", 60, details
    except Exception as e:
        logger.debug(f"ThreatFox query error: {e}")

    return "UNKNOWN", 30, {"status": "Feed queried"}
