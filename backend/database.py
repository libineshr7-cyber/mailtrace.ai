"""
MAILTRACE AI — SQLite Database Layer
Stores investigations, parsed dossiers, IOCs, audit logs, and system settings.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_PATH = os.getenv("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "mailtrace.db"))

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite tables and seeds baseline realistic data if empty."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS investigations (
        id TEXT PRIMARY KEY,
        case_id TEXT UNIQUE NOT NULL,
        subject TEXT NOT NULL,
        sender TEXT NOT NULL,
        sender_domain TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        auth_status TEXT NOT NULL,
        ioc_count INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'INVESTIGATING',
        analyst TEXT NOT NULL DEFAULT 'Automated DFIR Engine',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        dossier_json TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        user TEXT NOT NULL,
        action TEXT NOT NULL,
        case_id TEXT,
        object TEXT NOT NULL,
        result TEXT NOT NULL,
        details TEXT,
        ip_address TEXT DEFAULT '127.0.0.1'
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    conn.commit()

    # Seed baseline cases if empty
    cursor.execute("SELECT COUNT(*) FROM investigations")
    count = cursor.fetchone()[0]
    if count == 0:
        seed_baseline_investigations(conn)

    conn.close()

def seed_baseline_investigations(conn):
    """Seeds baseline realistic investigations with complete forensic payloads."""
    cursor = conn.cursor()

    now = datetime.now(timezone.utc).isoformat()

    # Case 1: Urgent Invoice Spearphishing (Critical)
    case1_id = "inv-0142"
    case1_dossier = {
        "headers": {
            "investigationId": case1_id,
            "rawHeaders": [
                {"name": "From", "value": '"Accounts Billing" <billing@secure-payments.example>', "isSuspicious": False},
                {"name": "To", "value": '"Finance Operations" <finance@company.internal>', "isSuspicious": False},
                {"name": "Date", "value": now, "isSuspicious": False},
                {"name": "Subject", "value": "Urgent Invoice Payment Required - INV-2026-8891", "isSuspicious": False},
                {"name": "Message-ID", "value": "<20260904142218.8891@secure-payments.example>", "isSuspicious": False},
                {"name": "Return-Path", "value": "<bounce-relay@compromised-host.xyz>", "isSuspicious": True, "notes": "Envelope Return-Path domain differs from From domain"},
                {"name": "Authentication-Results", "value": "mx.company.internal; spf=fail (domain secure-payments.example does not designate 185.220.101.47) smtp.mailfrom=billing@secure-payments.example; dkim=pass (2048-bit key) header.d=secure-payments.example header.s=20230630; dmarc=fail (p=reject dis=quarantine) header.from=secure-payments.example;", "isSuspicious": True},
                {"name": "Received", "value": "from mail-relay.secure-payments.example (mail-relay.secure-payments.example [185.220.101.47]) by mx.company.internal with ESMTP id MT882190; Fri, 04 Sep 2026 14:23:42 +0000", "isSuspicious": False},
            ],
            "receivedChain": [
                {
                    "hopIndex": 1,
                    "from": "mail-relay.secure-payments.example",
                    "by": "mx.company.internal",
                    "with": "ESMTP",
                    "forAddress": "finance@company.internal",
                    "timestamp": now,
                    "ip": "185.220.101.47",
                    "hostname": "mail-relay.secure-payments.example",
                    "country": "Netherlands",
                    "city": "Amsterdam",
                    "isSuspicious": True,
                    "delaySeconds": 2
                }
            ],
            "suspiciousHeaders": [
                {"name": "Return-Path", "value": "<bounce-relay@compromised-host.xyz>", "isSuspicious": True, "notes": "Return-Path mismatch"}
            ],
            "forgedFields": ["Return-Path / From Domain Mismatch", "SPF Authorized IP Mismatch"]
        },
        "authentication": {
            "investigationId": case1_id,
            "spf": {
                "result": "FAIL",
                "domain": "secure-payments.example",
                "sendingIp": "185.220.101.47",
                "mechanism": "-all",
                "explanation": "Sending IP 185.220.101.47 is not designated in DNS SPF record for secure-payments.example."
            },
            "dkim": {
                "result": "PASS",
                "domain": "secure-payments.example",
                "selector": "20230630",
                "algorithm": "rsa-sha256",
                "bodyHashVerified": True
            },
            "dmarc": {
                "result": "FAIL",
                "policy": "reject",
                "spfAlignment": "FAIL",
                "dkimAlignment": "PASS",
                "pct": 100
            },
            "senderPathStatus": "FAIL",
            "engine": "RFC 7208 / RFC 6376 / RFC 7489 Live DNS Verifier"
        },
        "iocs": [
            {
                "id": "ioc-1",
                "investigationId": case1_id,
                "indicator": "185.220.101.47",
                "type": "IP",
                "verdict": "MALICIOUS",
                "confidence": 94,
                "firstSeen": now,
                "lastSeen": now,
                "source": "AbuseIPDB & ThreatFox",
                "tags": ["phishing-relay", "c2-proxy"],
                "relatedCases": ["CASE-2026-0142"],
                "country": "Netherlands",
                "asn": "AS209650",
                "organization": "Abuse Hosting LLC"
            },
            {
                "id": "ioc-2",
                "investigationId": case1_id,
                "indicator": "http://verify-secure-portal.nl/update",
                "type": "URL",
                "verdict": "MALICIOUS",
                "confidence": 98,
                "firstSeen": now,
                "lastSeen": now,
                "source": "URLhaus Feed",
                "tags": ["credential-harvester", "banking-lure"],
                "relatedCases": ["CASE-2026-0142"],
                "country": "Netherlands",
                "asn": "AS209650",
                "organization": "Abuse Hosting LLC"
            },
            {
                "id": "ioc-3",
                "investigationId": case1_id,
                "indicator": "secure-payments.example",
                "type": "DOMAIN",
                "verdict": "SUSPICIOUS",
                "confidence": 78,
                "firstSeen": now,
                "lastSeen": now,
                "source": "RDAP WHOIS",
                "tags": ["typosquatting", "young-domain"],
                "relatedCases": ["CASE-2026-0142"]
            },
            {
                "id": "ioc-4",
                "investigationId": case1_id,
                "indicator": "7d9178a3c4e5f601b2a3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5",
                "type": "HASH",
                "verdict": "SUSPICIOUS",
                "confidence": 85,
                "firstSeen": now,
                "lastSeen": now,
                "source": "Static Byte Parser",
                "tags": ["pdf-embedded-js"],
                "relatedCases": ["CASE-2026-0142"]
            }
        ],
        "attachments": [
            {
                "id": "att-1",
                "investigationId": case1_id,
                "filename": "Invoice_INV-2026-8891.pdf",
                "mimeType": "application/pdf",
                "size": 48210,
                "sha256": "7d9178a3c4e5f601b2a3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5",
                "md5": "e4d909c290d0fb1ca068ffaddf22cbd0",
                "sha1": "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
                "verdict": "SUSPICIOUS",
                "analysisNotes": [
                    "PDF document contains embedded JavaScript object stream (/JavaScript)",
                    "Document includes external URI redirect pointing to credential capture portal"
                ],
                "macros": False,
                "links": ["http://verify-secure-portal.nl/update"],
                "engine": "MIME Static Inspector v2.1"
            }
        ],
        "infrastructure": [
            {
                "id": "inf-1",
                "investigationId": case1_id,
                "ip": "185.220.101.47",
                "hostname": "mail-relay.secure-payments.example",
                "asn": "AS209650",
                "organization": "Abuse Hosting LLC",
                "country": "Netherlands",
                "region": "North Holland",
                "city": "Amsterdam",
                "latitude": 52.3676,
                "longitude": 4.9041,
                "riskLevel": "CRITICAL",
                "role": "SENDER",
                "sources": ["IP-API", "AbuseIPDB", "BGP Routing Table"]
            }
        ],
        "risk": {
            "investigationId": case1_id,
            "totalScore": 88,
            "maxScore": 100,
            "riskLevel": "CRITICAL",
            "breakdown": {
                "authentication": {"score": 22, "max": 25},
                "iocReputation": {"score": 24, "max": 25},
                "infrastructureRisk": {"score": 15, "max": 20},
                "urlAnalysis": {"score": 15, "max": 15},
                "attachmentRisk": {"score": 12, "max": 15}
            },
            "factors": [
                {
                    "id": "rf-1",
                    "category": "Authentication",
                    "factor": "SPF validation failed for sending IP",
                    "impact": 10,
                    "evidence": "Sending IP 185.220.101.47 not permitted by secure-payments.example SPF record",
                    "severity": "CRITICAL"
                },
                {
                    "id": "rf-2",
                    "category": "Authentication",
                    "factor": "DMARC reject policy enforced",
                    "impact": 12,
                    "evidence": "From header domain failed SPF alignment with p=reject policy",
                    "severity": "CRITICAL"
                },
                {
                    "id": "rf-3",
                    "category": "Threat Intelligence",
                    "factor": "Active phishing URL verified by URLhaus",
                    "impact": 15,
                    "evidence": "http://verify-secure-portal.nl/update matched known credential harvesting campaign",
                    "severity": "CRITICAL"
                },
                {
                    "id": "rf-4",
                    "category": "Infrastructure",
                    "factor": "Originating IP hosted on flagged abuse AS209650",
                    "impact": 15,
                    "evidence": "AbuseIPDB reports 94% confidence of abusive activity",
                    "severity": "CRITICAL"
                }
            ],
            "engine": "Explainable Threat Heuristic Scorer",
            "engineVersion": "2.4.0"
        },
        "timeline": [
            {
                "id": "tl-1",
                "investigationId": case1_id,
                "timestamp": now,
                "category": "SYSTEM",
                "event": "Email Artifact Ingested",
                "evidence": "MIME stream received: Invoice_INV-2026-8891.eml (48,210 bytes). Calculated FIPS 180-4 SHA-256.",
                "source": "Ingress Pipeline",
                "severity": "NONE"
            },
            {
                "id": "tl-2",
                "investigationId": case1_id,
                "timestamp": now,
                "category": "AUTHENTICATION",
                "event": "SPF & DMARC Alignment Evaluation Failed",
                "evidence": "SPF returned FAIL (Sending IP 185.220.101.47). DMARC quarantine policy enacted.",
                "source": "Authentication Engine",
                "severity": "CRITICAL"
            },
            {
                "id": "tl-3",
                "investigationId": case1_id,
                "timestamp": now,
                "category": "IOC",
                "event": "Malicious Credential Phishing URL Extracted",
                "evidence": "URLhaus verified http://verify-secure-portal.nl/update as active credential capture endpoint.",
                "source": "Threat Intelligence Bridge",
                "severity": "CRITICAL"
            },
            {
                "id": "tl-4",
                "investigationId": case1_id,
                "timestamp": now,
                "category": "ANALYST",
                "event": "Quarantine Enforced at Gateway",
                "evidence": "Message revoked from recipient exchange mailboxes. Border firewall block dispatched.",
                "source": "Incident Response Automated Action",
                "severity": "HIGH"
            }
        ],
        "graph": {
            "investigationId": case1_id,
            "nodes": [
                {"id": "n-email", "type": "EMAIL", "label": "INV-2026-8891", "riskLevel": "CRITICAL", "data": {"subject": "Urgent Invoice Payment Required"}},
                {"id": "n-sender", "type": "SENDER", "label": "billing@secure-payments.example", "riskLevel": "HIGH", "data": {"domain": "secure-payments.example"}},
                {"id": "n-domain", "type": "DOMAIN", "label": "secure-payments.example", "riskLevel": "MEDIUM", "data": {"status": "unaligned"}},
                {"id": "n-ip", "type": "IP", "label": "185.220.101.47", "riskLevel": "CRITICAL", "data": {"asn": "AS209650", "country": "Netherlands"}},
                {"id": "n-url", "type": "URL", "label": "http://verify-secure-portal.nl/update", "riskLevel": "CRITICAL", "data": {"threat": "phishing"}},
                {"id": "n-att", "type": "ATTACHMENT", "label": "Invoice_INV-2026-8891.pdf", "riskLevel": "HIGH", "data": {"sha256": "7d9178a3c4e5..."}}
            ],
            "edges": [
                {"id": "e-1", "source": "n-email", "target": "n-sender", "label": "SENT_FROM"},
                {"id": "e-2", "source": "n-sender", "target": "n-domain", "label": "MATCHES"},
                {"id": "e-3", "source": "n-domain", "target": "n-ip", "label": "RESOLVES_TO"},
                {"id": "e-4", "source": "n-email", "target": "n-url", "label": "CONTAINS"},
                {"id": "e-5", "source": "n-email", "target": "n-att", "label": "CONTAINS"}
            ]
        }
    }

    cursor.execute("""
    INSERT INTO investigations (
        id, case_id, subject, sender, sender_domain, risk_level, risk_score,
        auth_status, ioc_count, status, analyst, created_at, updated_at,
        file_hash, file_name, file_size, dossier_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case1_id,
        "CASE-2026-0142",
        "Urgent Invoice Payment Required - INV-2026-8891",
        "billing@secure-payments.example",
        "secure-payments.example",
        "CRITICAL",
        88,
        "FAIL",
        4,
        "INVESTIGATING",
        "Automated DFIR Engine",
        now,
        now,
        "7d9178a3c4e5f601b2a3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5",
        "Invoice_INV-2026-8891.eml",
        48210,
        json.dumps(case1_dossier)
    ))

    # Audit logs seed
    cursor.execute("""
    INSERT INTO audit_logs (id, timestamp, user, action, case_id, object, result, details, ip_address)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "log-1", now, "Automated DFIR Engine", "COMPLETED_ANALYSIS", "CASE-2026-0142",
        "Invoice_INV-2026-8891.eml", "SUCCESS", "Calculated Risk Score 88/100 (CRITICAL). Quarantined at gateway.", "127.0.0.1"
    ))

    conn.commit()


def save_investigation(inv_data: Dict[str, Any], dossier: Dict[str, Any]):
    """Inserts or updates an investigation and its full forensic dossier."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT OR REPLACE INTO investigations (
        id, case_id, subject, sender, sender_domain, risk_level, risk_score,
        auth_status, ioc_count, status, analyst, created_at, updated_at,
        file_hash, file_name, file_size, dossier_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        inv_data["id"],
        inv_data["caseId"],
        inv_data["subject"],
        inv_data["sender"],
        inv_data["senderDomain"],
        inv_data["riskLevel"],
        inv_data["riskScore"],
        inv_data["authStatus"],
        inv_data["iocCount"],
        inv_data.get("status", "INVESTIGATING"),
        inv_data.get("analyst", "Automated DFIR Engine"),
        inv_data["createdAt"],
        inv_data["updatedAt"],
        inv_data["fileHash"],
        inv_data["fileName"],
        inv_data["fileSize"],
        json.dumps(dossier)
    ))

    # Log audit event
    cursor.execute("""
    INSERT INTO audit_logs (id, timestamp, user, action, case_id, object, result, details, ip_address)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        f"log-{datetime.now(timezone.utc).timestamp()}",
        inv_data["updatedAt"],
        inv_data.get("analyst", "Automated DFIR Engine"),
        "COMPLETED_ANALYSIS",
        inv_data["caseId"],
        inv_data["fileName"],
        "SUCCESS",
        f"Calculated Risk Score {inv_data['riskScore']}/100 ({inv_data['riskLevel']}) with {inv_data['iocCount']} IOCs extracted.",
        "127.0.0.1"
    ))

    conn.commit()
    conn.close()


def get_all_investigations() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, case_id, subject, sender, sender_domain, risk_level, risk_score,
           auth_status, ioc_count, status, analyst, created_at, updated_at,
           file_hash, file_name, file_size
    FROM investigations ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "caseId": r["case_id"],
            "subject": r["subject"],
            "sender": r["sender"],
            "senderDomain": r["sender_domain"],
            "riskLevel": r["risk_level"],
            "riskScore": r["risk_score"],
            "authStatus": r["auth_status"],
            "iocCount": r["ioc_count"],
            "status": r["status"],
            "analyst": r["analyst"],
            "createdAt": r["created_at"],
            "updatedAt": r["updated_at"],
            "fileHash": r["file_hash"],
            "fileName": r["file_name"],
            "fileSize": r["file_size"],
        })
    return results


def get_investigation_by_id(inv_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM investigations WHERE id = ? OR case_id = ?", (inv_id, inv_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None

    return {
        "id": row["id"],
        "caseId": row["case_id"],
        "subject": row["subject"],
        "sender": row["sender"],
        "senderDomain": row["sender_domain"],
        "riskLevel": row["risk_level"],
        "riskScore": row["risk_score"],
        "authStatus": row["auth_status"],
        "iocCount": row["ioc_count"],
        "status": row["status"],
        "analyst": row["analyst"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
        "fileHash": row["file_hash"],
        "fileName": row["file_name"],
        "fileSize": row["file_size"],
    }


def get_dossier_by_id(inv_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT dossier_json FROM investigations WHERE id = ? OR case_id = ?", (inv_id, inv_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return json.loads(row["dossier_json"])


def get_all_iocs() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT dossier_json FROM investigations")
    rows = cursor.fetchall()
    conn.close()

    all_iocs = []
    seen = set()
    for r in rows:
        dossier = json.loads(r["dossier_json"])
        for ioc in dossier.get("iocs", []):
            key = f"{ioc.get('type')}:{ioc.get('indicator')}"
            if key not in seen:
                seen.add(key)
                all_iocs.append(ioc)
    return all_iocs


def get_all_infrastructure() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT dossier_json FROM investigations")
    rows = cursor.fetchall()
    conn.close()

    all_infra = []
    seen = set()
    for r in rows:
        dossier = json.loads(r["dossier_json"])
        for pt in dossier.get("infrastructure", []):
            key = pt.get("ip") or pt.get("hostname")
            if key and key not in seen:
                seen.add(key)
                all_infra.append(pt)
    return all_infra


def get_all_audit_logs() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for r in rows:
        logs.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "user": r["user"],
            "action": r["action"],
            "caseId": r["case_id"],
            "object": r["object"],
            "result": r["result"],
            "details": r["details"],
            "ipAddress": r["ip_address"]
        })
    return logs


def add_audit_log(user: str, action: str, case_id: Optional[str], obj: str, result: str, details: str = "", ip: str = "127.0.0.1"):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    INSERT INTO audit_logs (id, timestamp, user, action, case_id, object, result, details, ip_address)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        f"log-{datetime.now(timezone.utc).timestamp()}",
        now, user, action, case_id, obj, result, details, ip
    ))
    conn.commit()
    conn.close()
