"""
MAILTRACE AI — Explainable Threat Heuristic Risk Scorer
Computes deterministic, evidence-based composite risk scores and itemized factor impacts.
"""

from typing import List, Dict, Any, Tuple
from .models import RiskAssessment, RiskBreakdown, BreakdownItem, RiskFactor

def calculate_risk_assessment(
    investigation_id: str,
    auth_result: Dict[str, Any],
    iocs: List[Dict[str, Any]],
    attachments: List[Dict[str, Any]],
    forged_fields: List[str],
    body_text: str,
) -> RiskAssessment:
    """
    Computes an explainable 0-100 risk score with category breakdowns and itemized factors.
    """
    factors: List[RiskFactor] = []

    # 1. Authentication Scoring (Max: 25)
    auth_score = 0
    spf_res = auth_result.get("spf", {}).get("result", "UNKNOWN")
    dkim_res = auth_result.get("dkim", {}).get("result", "UNKNOWN")
    dmarc_res = auth_result.get("dmarc", {}).get("result", "UNKNOWN")

    if spf_res == "FAIL":
        auth_score += 10
        factors.append(RiskFactor(
            id=f"rf-auth-spf-{len(factors)+1}",
            category="Authentication",
            factor="SPF verification failed",
            impact=10,
            evidence=auth_result.get("spf", {}).get("explanation", "Originating IP not designated in domain SPF record"),
            severity="CRITICAL"
        ))
    elif spf_res == "SUSPICIOUS":
        auth_score += 6
        factors.append(RiskFactor(
            id=f"rf-auth-spf-{len(factors)+1}",
            category="Authentication",
            factor="SPF softfail policy restriction",
            impact=6,
            evidence="Originating IP softfailed domain SPF rule (~all)",
            severity="HIGH"
        ))

    if dmarc_res == "FAIL":
        auth_score += 12
        factors.append(RiskFactor(
            id=f"rf-auth-dmarc-{len(factors)+1}",
            category="Authentication",
            factor="DMARC alignment policy failed",
            impact=12,
            evidence=f"From domain alignment failed with published policy p={auth_result.get('dmarc', {}).get('policy', 'reject')}",
            severity="CRITICAL"
        ))
    elif dmarc_res == "SUSPICIOUS":
        auth_score += 5
        factors.append(RiskFactor(
            id=f"rf-auth-dmarc-{len(factors)+1}",
            category="Authentication",
            factor="DMARC policy warning",
            impact=5,
            evidence="DMARC published policy monitoring only",
            severity="MEDIUM"
        ))

    if dkim_res == "FAIL":
        auth_score += 3
        factors.append(RiskFactor(
            id=f"rf-auth-dkim-{len(factors)+1}",
            category="Authentication",
            factor="DKIM cryptographic signature check failed",
            impact=3,
            evidence="DKIM DNS public key mismatch or missing selector",
            severity="MEDIUM"
        ))

    auth_score = min(25, auth_score)

    # 2. IOC Reputation Scoring (Max: 25)
    ioc_score = 0
    malicious_iocs = [i for i in iocs if i.get("verdict") == "MALICIOUS"]
    suspicious_iocs = [i for i in iocs if i.get("verdict") == "SUSPICIOUS"]

    if malicious_iocs:
        added = min(25, len(malicious_iocs) * 12)
        ioc_score += added
        factors.append(RiskFactor(
            id=f"rf-ioc-mal-{len(factors)+1}",
            category="Threat Intelligence",
            factor=f"Confirmed malicious indicators identified ({len(malicious_iocs)})",
            impact=added,
            evidence=f"Threat feeds confirmed malicious indicators: {', '.join([m.get('indicator', '') for m in malicious_iocs[:2]])}",
            severity="CRITICAL"
        ))
    elif suspicious_iocs:
        added = min(15, len(suspicious_iocs) * 6)
        ioc_score += added
        factors.append(RiskFactor(
            id=f"rf-ioc-susp-{len(factors)+1}",
            category="Threat Intelligence",
            factor=f"Suspicious threat indicators flagged ({len(suspicious_iocs)})",
            impact=added,
            evidence=f"Reputation index flagged indicators: {', '.join([s.get('indicator', '') for s in suspicious_iocs[:2]])}",
            severity="HIGH"
        ))

    ioc_score = min(25, ioc_score)

    # 3. Infrastructure & Header Anomaly Scoring (Max: 20)
    infra_score = 0
    if forged_fields:
        added = min(15, len(forged_fields) * 7)
        infra_score += added
        factors.append(RiskFactor(
            id=f"rf-infra-forge-{len(factors)+1}",
            category="Infrastructure",
            factor="MIME header spoofing and forged envelope fields",
            impact=added,
            evidence=f"Detected forged fields: {', '.join(forged_fields)}",
            severity="HIGH"
        ))

    # Check for suspicious keywords in body
    phish_keywords = ["urgent", "wire payment", "invoice overdue", "suspend", "verify account", "reset password", "gift card", "crypto", "immediate action required"]
    body_lower = body_text.lower()
    keyword_hits = [kw for kw in phish_keywords if kw in body_lower]
    if len(keyword_hits) >= 2:
        infra_score += 5
        factors.append(RiskFactor(
            id=f"rf-body-keywords-{len(factors)+1}",
            category="Content Analysis",
            factor="Social engineering and high-urgency solicitation detected",
            impact=5,
            evidence=f"Matched urgency keywords: {', '.join(keyword_hits[:3])}",
            severity="MEDIUM"
        ))

    infra_score = min(20, infra_score)

    # 4. URL Analysis Scoring (Max: 15)
    url_score = 0
    url_iocs = [i for i in iocs if i.get("type") == "URL"]
    malicious_urls = [u for u in url_iocs if u.get("verdict") in ["MALICIOUS", "SUSPICIOUS"]]
    if malicious_urls:
        url_score = 15
        factors.append(RiskFactor(
            id=f"rf-url-phish-{len(factors)+1}",
            category="URL Security",
            factor="Malicious or deceptive phishing hyperlink detected in body",
            impact=15,
            evidence=f"Target URL: {malicious_urls[0].get('indicator')}",
            severity="CRITICAL"
        ))
    elif url_iocs:
        url_score = 3

    url_score = min(15, url_score)

    # 5. Attachment Risk Scoring (Max: 15)
    att_score = 0
    for att in attachments:
        v = att.get("verdict", "CLEAN")
        if v == "MALICIOUS":
            att_score = 15
            factors.append(RiskFactor(
                id=f"rf-att-mal-{len(factors)+1}",
                category="Attachment Risk",
                factor=f"Malicious payload payload identified in '{att.get('filename')}'",
                impact=15,
                evidence=f"{'; '.join(att.get('analysisNotes', ['Malicious payload detected']))}",
                severity="CRITICAL"
            ))
            break
        elif v == "SUSPICIOUS" or att.get("macros"):
            att_score = max(att_score, 10)
            factors.append(RiskFactor(
                id=f"rf-att-susp-{len(factors)+1}",
                category="Attachment Risk",
                factor=f"Suspicious payload characteristics in '{att.get('filename')}'",
                impact=10,
                evidence="Attachment contains embedded macros, scripts, or executable extensions",
                severity="HIGH"
            ))

    att_score = min(15, att_score)

    # Total Score
    total_score = auth_score + ioc_score + infra_score + url_score + att_score

    # Determine Risk Level
    if total_score >= 75:
        level = "CRITICAL"
    elif total_score >= 50:
        level = "HIGH"
    elif total_score >= 25:
        level = "MEDIUM"
    elif total_score >= 10:
        level = "LOW"
    else:
        level = "NONE"

    breakdown = RiskBreakdown(
        authentication=BreakdownItem(score=auth_score, max=25),
        iocReputation=BreakdownItem(score=ioc_score, max=25),
        infrastructureRisk=BreakdownItem(score=infra_score, max=20),
        urlAnalysis=BreakdownItem(score=url_score, max=15),
        attachmentRisk=BreakdownItem(score=att_score, max=15),
    )

    return RiskAssessment(
        investigationId=investigation_id,
        totalScore=total_score,
        maxScore=100,
        riskLevel=level,
        breakdown=breakdown,
        factors=factors,
        engine="Explainable Threat Heuristic Scorer",
        engineVersion="2.4.0"
    )
