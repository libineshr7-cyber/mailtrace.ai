"""
MAILTRACE AI — Enterprise MIME / RFC 5322 Email Parser
Performs byte-level dissection of email artifacts, header chains, and attachment payloads.
"""

import email
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional

from .models import EmailHeader, ReceivedHop, Attachment
from .ioc_extractor import extract_iocs_from_text, is_public_ip

# Regex to parse RFC 822 Received headers
# Example: from mail-relay.example.com (mail-relay.example.com [185.220.101.47]) by mx.corp.internal with ESMTP ... ; Fri, 04 Sep 2026 14:23:42 +0000
RECEIVED_PATTERN = re.compile(
    r'(?:from\s+(?P<from>[^\s\(;]+)(?:\s*\((?P<from_extra>[^;]+)\))?)?'
    r'(?:\s*by\s+(?P<by>[^\s\(;]+))?'
    r'(?:\s*with\s+(?P<with>[^\s;]+))?'
    r'(?:[^\;]*for\s*<(?P<for>[^>]+)>)?'
    r'(?:[^\;]*;\s*(?P<date>.+))?',
    re.IGNORECASE | re.DOTALL
)

def compute_hashes(data: bytes) -> Tuple[str, str, str]:
    """Computes SHA-256, MD5, and SHA-1 digests for a byte payload."""
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    return sha256, md5, sha1

def inspect_attachment_content(filename: str, mime_type: str, data: bytes) -> Tuple[str, List[str], bool, List[str]]:
    """
    Performs static structural inspection on attachment bytes.
    Returns: (verdict, analysisNotes, macros, links)
    """
    notes = []
    links = []
    has_macros = False
    verdict = "CLEAN"

    fn_lower = filename.lower()
    ext = fn_lower.split('.')[-1] if '.' in fn_lower else ''

    # Dangerous executable extensions
    dangerous_exts = {'exe', 'bat', 'cmd', 'scr', 'vbs', 'js', 'hta', 'ps1', 'iso', 'img', 'jar', 'pif'}
    macro_exts = {'docm', 'xlsm', 'pptm', 'dotm', 'xltm'}

    if ext in dangerous_exts:
        notes.append(f"Executable binary or script payload extension (.{ext}) detected in MIME stream")
        verdict = "MALICIOUS"
    elif ext in macro_exts:
        notes.append(f"Macro-enabled Office document format (.{ext}) identified")
        has_macros = True
        verdict = "SUSPICIOUS"

    # Static byte signature inspection
    if b'vbaProject.bin' in data or b'Sub AutoOpen' in data or b'Workbook_Open' in data:
        notes.append("Visual Basic for Applications (VBA) macro execution bytecode observed")
        has_macros = True
        verdict = "MALICIOUS"

    # PDF Inspection
    if ext == 'pdf' or b'%PDF' in data[:1024]:
        if b'/JavaScript' in data or b'/JS' in data:
            notes.append("Embedded Acrobat JavaScript action stream located in PDF object table")
            verdict = "MALICIOUS"
        if b'/Launch' in data:
            notes.append("Suspicious /Launch action detected (direct OS execution trigger)")
            verdict = "MALICIOUS"
        if b'/URI' in data or b'/Action' in data:
            notes.append("Embedded hyperlink navigation object present in document")
            if verdict == "CLEAN":
                verdict = "SUSPICIOUS"
            # Extract URLs from PDF stream
            try:
                pdf_text = data.decode('latin-1', errors='ignore')
                found = re.findall(r'/URI\s*\((https?://[^)]+)\)', pdf_text)
                for u in found:
                    links.append(u.strip())
            except Exception:
                pass

    # Generic extracted links
    if not links:
        try:
            sample_text = data[:50000].decode('utf-8', errors='ignore')
            extracted = extract_iocs_from_text(sample_text)
            links = list(extracted['URL'])[:5]
        except Exception:
            pass

    if not notes:
        notes.append("Standard binary MIME stream inspected; no immediate anomalous bytecode triggers found.")

    return verdict, notes, has_macros, links

def parse_received_header(header_value: str, idx: int) -> ReceivedHop:
    """Parses a single Received header line into a structured ReceivedHop."""
    clean_val = " ".join(header_value.split())
    match = RECEIVED_PATTERN.search(clean_val)

    from_host = None
    by_host = None
    with_proto = None
    for_addr = None
    ip_addr = None
    hop_date_str = None
    delay = 0

    if match:
        from_host = match.group("from")
        from_extra = match.group("from_extra") or ""
        by_host = match.group("by")
        with_proto = match.group("with")
        for_addr = match.group("for")
        hop_date_str = match.group("date")

        # Try extracting IP from from_extra e.g. "mail.com [185.220.101.47]"
        ip_match = re.search(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', from_extra or from_host or "")
        if ip_match:
            ip_addr = ip_match.group(0)

    # Parse timestamp
    timestamp = datetime.now(timezone.utc).isoformat()
    if hop_date_str:
        try:
            dt = parsedate_to_datetime(hop_date_str.strip())
            timestamp = dt.isoformat()
        except Exception:
            pass

    is_suspicious = False
    if ip_addr and not is_public_ip(ip_addr) and idx == 1:
        # If the ingress hop claims to be a private IP from the public internet
        is_suspicious = False
    elif ip_addr and is_public_ip(ip_addr):
        # Public IP in relay chain
        is_suspicious = False

    return ReceivedHop(
        hopIndex=idx,
        from_=from_host or "relay.mail-node",
        by=by_host or "ingress.gateway",
        with_=with_proto or "ESMTP",
        forAddress=for_addr,
        timestamp=timestamp,
        ip=ip_addr,
        hostname=from_host or ip_addr,
        isSuspicious=is_suspicious,
        delaySeconds=delay
    )

def parse_email_bytes(raw_bytes: bytes, filename: str = "email.eml") -> Dict[str, Any]:
    """
    Full RFC 5322 parser for raw email bytes.
    Returns: dictionary containing all metadata, parsed headers, received chain, body text/html, attachments, and hashes.
    """
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    sha256, md5, sha1 = compute_hashes(raw_bytes)
    file_size = len(raw_bytes)

    # Core headers
    subject = msg.get("Subject", "No Subject")
    from_raw = msg.get("From", "")
    from_name, from_email = parseaddr(from_raw)
    from_domain = from_email.split("@")[-1].lower() if "@" in from_email else "unknown.domain"

    to_raw = msg.get_all("To", [])
    to_list = [parseaddr(addr)[1] for sub in to_raw for addr in str(sub).split(",") if addr]

    cc_raw = msg.get_all("Cc", [])
    cc_list = [parseaddr(addr)[1] for sub in cc_raw for addr in str(sub).split(",") if addr]

    reply_to = msg.get("Reply-To")
    return_path = msg.get("Return-Path")
    message_id = msg.get("Message-ID", f"<{sha256[:16]}@ingress.mailtrace.internal>")

    # Date
    date_header = msg.get("Date")
    created_at = datetime.now(timezone.utc).isoformat()
    if date_header:
        try:
            created_at = parsedate_to_datetime(date_header).isoformat()
        except Exception:
            pass

    # Extract all raw headers
    raw_headers: List[EmailHeader] = []
    received_headers: List[str] = []
    suspicious_headers: List[EmailHeader] = []
    forged_fields: List[str] = []

    for k, v in msg.items():
        val_str = str(v).replace("\r\n", " ").replace("\n", " ").strip()
        is_susp = False
        notes = None

        if k.lower() == "received":
            received_headers.append(val_str)
        elif k.lower() == "reply-to" and from_email:
            # Check reply-to mismatch
            _, rep_email = parseaddr(val_str)
            if rep_email and rep_email.split("@")[-1].lower() != from_domain:
                is_susp = True
                notes = f"Reply-To domain ({rep_email.split('@')[-1]}) differs from From domain ({from_domain})"
                forged_fields.append("Reply-To / From Domain Discrepancy")
        elif k.lower() == "return-path" and from_email:
            _, ret_email = parseaddr(val_str)
            if ret_email and ret_email.split("@")[-1].lower() != from_domain:
                is_susp = True
                notes = f"Envelope sender Return-Path differs from From header: {ret_email}"
                forged_fields.append("Return-Path Mismatch")

        header_obj = EmailHeader(name=k, value=val_str, isSuspicious=is_susp, notes=notes)
        raw_headers.append(header_obj)
        if is_susp:
            suspicious_headers.append(header_obj)

    # Parse Received hop chain (reverse chronological order in email headers -> chronological order for analysis)
    received_chain: List[ReceivedHop] = []
    chronological_received = list(reversed(received_headers))
    prev_dt = None

    for idx, r_val in enumerate(chronological_received, start=1):
        hop = parse_received_header(r_val, idx)
        try:
            current_dt = datetime.fromisoformat(hop.timestamp)
            if prev_dt:
                hop.delaySeconds = max(0, int((current_dt - prev_dt).total_seconds()))
            prev_dt = current_dt
        except Exception:
            pass
        received_chain.append(hop)

    # Originating sending IP
    sending_ip = None
    for hop in received_chain:
        if hop.ip and is_public_ip(hop.ip):
            sending_ip = hop.ip
            break

    # Body extraction & Attachments
    body_text = ""
    body_html = ""
    attachments: List[Attachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            content_type = part.get_content_type()

            if "attachment" in content_disposition.lower() or part.get_filename():
                att_name = part.get_filename() or f"attachment_{len(attachments)+1}.bin"
                att_bytes = part.get_payload(decode=True) or b""
                att_sha256, att_md5, att_sha1 = compute_hashes(att_bytes)
                verdict, notes, macros, links = inspect_attachment_content(att_name, content_type, att_bytes)

                att_obj = Attachment(
                    id=f"att-{att_sha256[:8]}",
                    investigationId="",
                    filename=att_name,
                    mimeType=content_type,
                    size=len(att_bytes),
                    sha256=att_sha256,
                    md5=att_md5,
                    sha1=att_sha1,
                    verdict=verdict,
                    analysisNotes=notes,
                    macros=macros,
                    links=links
                )
                attachments.append(att_obj)
            elif content_type == "text/plain":
                part_payload = part.get_payload(decode=True)
                if part_payload:
                    body_text += part_payload.decode("utf-8", errors="ignore") + "\n"
            elif content_type == "text/html":
                part_payload = part.get_payload(decode=True)
                if part_payload:
                    body_html += part_payload.decode("utf-8", errors="ignore") + "\n"
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            text = payload.decode("utf-8", errors="ignore")
            if content_type == "text/html":
                body_html = text
            else:
                body_text = text

    return {
        "fileName": filename,
        "fileSize": file_size,
        "fileHash": sha256,
        "md5": md5,
        "sha1": sha1,
        "subject": subject,
        "from": from_raw,
        "fromEmail": from_email,
        "fromDomain": from_domain,
        "to": to_list,
        "cc": cc_list,
        "replyTo": reply_to,
        "returnPath": return_path,
        "messageId": message_id,
        "createdAt": created_at,
        "rawHeaders": raw_headers,
        "receivedChain": received_chain,
        "suspiciousHeaders": suspicious_headers,
        "forgedFields": forged_fields,
        "sendingIp": sending_ip,
        "bodyText": body_text,
        "bodyHtml": body_html,
        "attachments": attachments,
    }
