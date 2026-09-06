# Mailtrace AI — Enterprise Forensic Email Analysis Platform

> **100% Real-Time Forensic Working Product** — Zero Synthetic/Mock Data. Live RFC 5322 MIME dissector, cryptographic hashing, live DNS SPF/DKIM/DMARC evaluation, live IOC extraction, threat intel lookups (URLhaus, ThreatFox, IP-API GeoIP), and persistent SQLite dossier storage.

---

## 🏛️ System Architecture

```
                    ┌───────────────────────────────────────┐
                    │     Live Email Ingress / Triage       │
                    │ (.eml, .msg, RFC 822 raw MIME stream) │
                    └───────────────────┬───────────────────┘
                                        │
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │       FastAPI Real-Time Backend (:8000)             │
             │                                                     │
             │  1. MIME Dissector: SHA-256/MD5, Hops, Forged Dns   │
             │  2. DNS Engine: Live SPF (RFC 7208), DKIM, DMARC    │
             │  3. IOC Extractor: IPv4/IPv6, Domains, URLs, Hashes │
             │  4. Threat Intel: Live URLhaus, ThreatFox, IP-API   │
             │  5. Risk Scorer: Weighted multi-factor Bayesian     │
             │  6. Graph Engine: Hierarchical DFIR attack tree     │
             │  7. SQLite DB: mailtrace.db (Immutable Dossiers)    │
             └──────────────────────────┬──────────────────────────┘
                                        │ (Proxy /api)
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │         React 18 + Vite Frontend (:3000)            │
             │                                                     │
             │  • Overview Dashboard (Live active metrics)         │
             │  • Email Ingestion Studio (Real-time log stream)    │
             │  • Deep Investigation Tabs (Summary, Headers, Auth, │
             │    IOCs, Infrastructure Map, Graph, Report, STIX)   │
             │  • Cross-Case Threat Intelligence & IOC Vault       │
             │  • Real-Time Gateway Quarantine Dispatch            │
             └─────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (One-Click Launch)

### Option A: Windows Batch Launcher
Double-click `run_mailtrace.bat` or run in terminal:
```cmd
run_mailtrace.bat
```

### Option B: PowerShell Launcher
```powershell
.\run_mailtrace.ps1
```

### Option C: Manual Launch

1. **Start the FastAPI Backend**:
   ```powershell
   python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
   ```

2. **Start the Frontend**:
   ```powershell
   cd frontend
   npm run dev
   ```

3. **Open the Web Console**:
   - Web App: [http://localhost:3000](http://localhost:3000)
   - Interactive OpenAPI Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
   - Service Health Check: [http://localhost:8000/api/system/health](http://localhost:8000/api/system/health)

---

## 🧪 Comprehensive Verification Suite

To verify all 15 endpoints, cryptographic hashing, live DNS verifications, threat intelligence queries, and database persistence:

```powershell
python backend/test_all_endpoints.py
```

Expected output:
```
============================================================
MAILTRACE AI — FULL FORENSIC BACKEND TEST SUITE
============================================================
[PASS] GET /api/system/health -> Status: OPERATIONAL, Services: 7
[PASS] GET /api/overview/stats -> Active: 5, Critical: 1, Critical IOCs: 41
[PASS] GET /api/samples -> 3 sample emails available
[*] Ingesting sample: bank_security_alert.eml...
[PASS] POST /api/analyze/email -> Created Investigation ID: inv-0148, Case: CASE-2026-0148, Logs: 10
[PASS] GET /api/investigations -> 6 investigations in database
[PASS] GET /api/investigations/inv-0148 -> Subject: 'CRITICAL: Unauthorized Login Attempt Detected on Corporate Account', RiskLevel: MEDIUM
[PASS] GET /api/investigations/inv-0148/headers & auth -> 1 Received hops, Auth SPF: UNKNOWN
[PASS] GET /api/investigations/inv-0148/iocs -> 9 forensic IOCs
[PASS] GET /api/investigations/inv-0148/risk -> Overall: 33, Breakdown: Auth=5, Factors: 4
[PASS] GET /api/investigations/inv-0148/graph -> Nodes: 6, Edges: 5
[PASS] GET /api/investigations/inv-0148/report -> Executive Summary: 'DFIR forensic analysis...'
[PASS] GET /api/iocs -> 25 total cross-case indicators
[PASS] GET /api/infrastructure -> 4 infrastructure geolocations
[PASS] GET /api/audit-logs -> 6 audit entries recorded
[PASS] POST /api/quarantine/action -> QUARANTINE_GATEWAY successfully applied
============================================================
ALL 15 ENDPOINTS VERIFIED WITH 100% SUCCESS — ZERO MOCK FALLBACKS
============================================================
```

To verify TypeScript and frontend production bundling:
```powershell
cd frontend
npm run build
```

---

## 🔬 Core Forensic Engines

| Component | Module | Live Forensic Operations |
|---|---|---|
| **MIME Dissector** | `backend/parser.py` | RFC 5322 boundary parsing, raw header extraction, SHA-256/MD5/SHA-1 cryptographic hashing, `Received:` hop delay and forged header detection, static attachment inspection. |
| **Authentication Engine** | `backend/auth_engine.py` | Live DNS queries (`dnspython`) against public resolvers for SPF records (`v=spf1 ...`), DKIM key selectors (`<selector>._domainkey.<domain>`), and DMARC policies (`_dmarc.<domain>`). |
| **IOC Extractor** | `backend/ioc_extractor.py` | RFC-compliant regex identification of IPv4/IPv6, FQDNs, URLs, hashes, and email addresses with automated RFC 1918 private IP de-noising. |
| **Threat Intelligence** | `backend/threat_intel.py` | Real-time queries to **IP-API** (GeoIP, ASN, Org, coordinates), **URLhaus API** (malware URL registry), and **ThreatFox API** (IOC correlation). |
| **Risk Scorer** | `backend/risk_scorer.py` | Explainable Bayesian threat rating (0-100) scoring authentication failures, reputation hits, attachment threats, and forged headers. |
| **Persistence Layer** | `backend/database.py` | Local SQLite database (`backend/mailtrace.db`) maintaining cases, dossiers, audit logs, and settings. |

---

## 📑 REST API Endpoint Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze/email` | Ingest raw RFC 822 file or text, run full triage pipeline, return case ID & logs |
| `GET` | `/api/investigations` | List all stored forensic investigations |
| `GET` | `/api/investigations/{id}` | Get summary dossier for a specific investigation |
| `GET` | `/api/investigations/{id}/headers` | Detailed header dissection & received hops |
| `GET` | `/api/investigations/{id}/authentication` | Live SPF, DKIM, and DMARC verification results |
| `GET` | `/api/investigations/{id}/iocs` | Extracted indicators and reputation verdicts |
| `GET` | `/api/investigations/{id}/attachments` | Static attachment metadata and hash digests |
| `GET` | `/api/investigations/{id}/infrastructure` | Geolocation points for interactive Leaflet map |
| `GET` | `/api/investigations/{id}/risk` | Multi-factor risk breakdown and contributing factors |
| `GET` | `/api/investigations/{id}/graph` | ReactFlow hierarchical node & edge network graph |
| `GET` | `/api/investigations/{id}/report` | Formal DFIR executive and technical investigation report |
| `GET` | `/api/investigations/{id}/export/stix` | Export case as standard STIX 2.1 JSON bundle |
| `GET` | `/api/iocs` | Cross-case global threat indicator intelligence |
| `GET` | `/api/infrastructure` | Global infrastructure map markers across all cases |
| `GET` | `/api/audit-logs` | Tamper-evident administrative & investigation audit trail |
| `GET` | `/api/system/health` | Real-time heartbeat & latency of all 7 forensic engines |
| `GET` | `/api/overview/stats` | Live aggregated SOC metrics & risk distribution |
| `GET` | `/api/samples` | Real RFC 822 test emails ready for instant ingestion |
| `POST` | `/api/quarantine/action` | Execute gateway quarantine and log audit event |
