"""
MAILTRACE AI — Pydantic Data Models
Defines all schema types for investigation dossiers, IOCs, headers, authentication, and reports.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# ---- Enums / Literal-like Types ----
RiskLevel = str  # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'
AuthResult = str  # 'PASS' | 'FAIL' | 'PARTIAL' | 'UNKNOWN' | 'SUSPICIOUS'
IOCType = str  # 'IP' | 'DOMAIN' | 'URL' | 'HASH' | 'EMAIL' | 'ATTACHMENT'
IOCVerdict = str  # 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN'
CaseStatus = str  # 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'ARCHIVED'


# ---- Investigation Core ----

class Investigation(BaseModel):
    id: str
    caseId: str
    subject: str
    sender: str
    senderDomain: str
    riskLevel: RiskLevel
    riskScore: int
    authStatus: AuthResult
    iocCount: int
    status: CaseStatus = "INVESTIGATING"
    analyst: str = "Automated DFIR Engine"
    createdAt: str
    updatedAt: str
    fileHash: str
    fileName: str
    fileSize: int


# ---- Headers ----

class EmailHeader(BaseModel):
    name: str
    value: str
    isSuspicious: bool = False
    notes: Optional[str] = None


class ReceivedHop(BaseModel):
    hopIndex: int
    from_: Optional[str] = Field(None, alias="from")
    by: Optional[str] = None
    with_: Optional[str] = Field(None, alias="with")
    forAddress: Optional[str] = None
    timestamp: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    isSuspicious: bool = False
    delaySeconds: Optional[int] = 0

    class Config:
        populate_by_name = True


class HeaderAnalysis(BaseModel):
    investigationId: str
    rawHeaders: List[EmailHeader]
    receivedChain: List[ReceivedHop]
    suspiciousHeaders: List[EmailHeader] = []
    forgedFields: List[str] = []


# ---- Authentication ----

class SPFResult(BaseModel):
    result: AuthResult
    domain: str
    sendingIp: str
    mechanism: Optional[str] = None
    explanation: Optional[str] = None


class DKIMResult(BaseModel):
    result: AuthResult
    domain: str
    selector: Optional[str] = None
    algorithm: Optional[str] = None
    bodyHashVerified: Optional[bool] = False


class DMARCResult(BaseModel):
    result: AuthResult
    policy: str
    spfAlignment: AuthResult
    dkimAlignment: AuthResult
    pct: Optional[int] = 100
    reportUri: Optional[str] = None


class AuthenticationResult(BaseModel):
    investigationId: str
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    senderPathStatus: AuthResult
    engine: str = "RFC 7208 / RFC 6376 / RFC 7489 Live DNS Verifier"


# ---- Indicators of Compromise (IOCs) ----

class IOC(BaseModel):
    id: str
    investigationId: str
    indicator: str
    type: IOCType
    verdict: IOCVerdict
    confidence: int  # 0-100
    firstSeen: str
    lastSeen: str
    source: str
    tags: List[str] = []
    relatedCases: List[str] = []
    country: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None


# ---- Attachments ----

class Attachment(BaseModel):
    id: str
    investigationId: str
    filename: str
    mimeType: str
    size: int
    sha256: str
    md5: Optional[str] = None
    sha1: Optional[str] = None
    verdict: IOCVerdict
    analysisNotes: List[str] = []
    macros: Optional[bool] = False
    links: Optional[List[str]] = []
    engine: str = "MIME Static Inspector v2.1"


# ---- Infrastructure ----

class InfrastructurePoint(BaseModel):
    id: str
    investigationId: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    country: str
    region: str
    city: str
    latitude: float
    longitude: float
    riskLevel: RiskLevel
    role: str  # 'SENDER' | 'RELAY' | 'DOMAIN_HOST' | 'REDIRECT' | 'C2' | 'UNKNOWN'
    sources: List[str] = []


# ---- Threat Intelligence ----

class ThreatIntelResult(BaseModel):
    id: str
    investigationId: str
    indicator: str
    source: str
    verdict: IOCVerdict
    confidence: int
    details: Optional[Dict[str, Any]] = None
    lastChecked: str
    available: bool = True
    rawResponse: Optional[str] = None


# ---- Timeline ----

class TimelineEvent(BaseModel):
    id: str
    investigationId: str
    timestamp: str
    category: str  # 'AUTHENTICATION' | 'IOC' | 'NETWORK' | 'THREAT_INTEL' | 'ANALYST' | 'SYSTEM'
    event: str
    evidence: str
    source: str
    severity: RiskLevel


# ---- Graph ----

class GraphNode(BaseModel):
    id: str
    type: str  # 'EMAIL' | 'SENDER' | 'REPLY_TO' | 'DOMAIN' | 'URL' | 'IP' | 'ASN' | 'ATTACHMENT' | 'HASH'
    label: str
    data: Dict[str, Any] = {}
    riskLevel: Optional[RiskLevel] = None
    verdict: Optional[IOCVerdict] = None


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str


class InvestigationGraph(BaseModel):
    investigationId: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]


# ---- Risk Assessment ----

class RiskFactor(BaseModel):
    id: str
    category: str
    factor: str
    impact: int
    evidence: str
    severity: RiskLevel


class BreakdownItem(BaseModel):
    score: int
    max: int


class RiskBreakdown(BaseModel):
    authentication: BreakdownItem
    iocReputation: BreakdownItem
    infrastructureRisk: BreakdownItem
    urlAnalysis: BreakdownItem
    attachmentRisk: BreakdownItem


class RiskAssessment(BaseModel):
    investigationId: str
    totalScore: int
    maxScore: int = 100
    riskLevel: RiskLevel
    breakdown: RiskBreakdown
    factors: List[RiskFactor]
    engine: str = "Explainable Threat Heuristic Scorer"
    engineVersion: str = "2.4.0"


# ---- Audit Logs ----

class AuditLog(BaseModel):
    id: str
    timestamp: str
    user: str
    action: str
    caseId: Optional[str] = None
    object: str
    result: str  # 'SUCCESS' | 'FAILURE' | 'WARNING'
    details: Optional[str] = None
    ipAddress: Optional[str] = "127.0.0.1"


# ---- System Health ----

class ServiceStatus(BaseModel):
    name: str
    description: str
    status: str  # 'OPERATIONAL' | 'DEGRADED' | 'OFFLINE'
    latency: Optional[int] = 12
    version: Optional[str] = "1.0.0"


class SystemHealth(BaseModel):
    overall: str
    services: List[ServiceStatus]
    lastChecked: str


# ---- Ingestion Response ----

class AnalyzeEmailResponse(BaseModel):
    investigationId: str
    caseId: str
    logs: List[Dict[str, Any]] = []


# ---- Global Overview Stats ----

class OverviewStats(BaseModel):
    activeInvestigations: int
    criticalCases: int
    criticalIOCs: int
    correlatedCampaigns: int
    threatDistribution: Dict[str, int]
