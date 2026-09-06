// ============================================================
// MAILTRACE AI — Core TypeScript Interfaces
// Mirrors the FastAPI backend data models
// ============================================================

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
export type AuthResult = 'PASS' | 'FAIL' | 'PARTIAL' | 'UNKNOWN' | 'SUSPICIOUS';
export type IOCType = 'IP' | 'DOMAIN' | 'URL' | 'HASH' | 'EMAIL' | 'ATTACHMENT';
export type IOCVerdict = 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
export type CaseStatus = 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'ARCHIVED';

// ---- Investigation ----

export interface Investigation {
  id: string;
  caseId: string;
  subject: string;
  sender: string;
  senderDomain: string;
  riskLevel: RiskLevel;
  riskScore: number;
  authStatus: AuthResult;
  iocCount: number;
  status: CaseStatus;
  analyst: string;
  createdAt: string;
  updatedAt: string;
  fileHash: string;
  fileName: string;
  fileSize: number;
}

// ---- Email ----

export interface EmailMeta {
  id: string;
  investigationId: string;
  messageId: string;
  subject: string;
  from: string;
  to: string[];
  cc: string[];
  replyTo?: string;
  returnPath?: string;
  date: string;
  receivedAt: string;
  fileName: string;
  fileSize: number;
  sha256: string;
  mimeType: string;
  bodyText?: string;
  bodyHtml?: string;
}

// ---- Email Headers ----

export interface EmailHeader {
  name: string;
  value: string;
  isSuspicious?: boolean;
  notes?: string;
}

export interface ReceivedHop {
  hopIndex: number;
  from?: string;
  by?: string;
  with?: string;
  forAddress?: string;
  timestamp: string;
  ip?: string;
  hostname?: string;
  country?: string;
  city?: string;
  isSuspicious?: boolean;
  delaySeconds?: number;
}

export interface HeaderAnalysis {
  investigationId: string;
  rawHeaders: EmailHeader[];
  receivedChain: ReceivedHop[];
  suspiciousHeaders: EmailHeader[];
  forgedFields: string[];
}

// ---- Authentication ----

export interface SPFResult {
  result: AuthResult;
  domain: string;
  sendingIp: string;
  mechanism?: string;
  explanation?: string;
}

export interface DKIMResult {
  result: AuthResult;
  domain: string;
  selector?: string;
  algorithm?: string;
  bodyHashVerified?: boolean;
}

export interface DMARCResult {
  result: AuthResult;
  policy: string;
  spfAlignment: AuthResult;
  dkimAlignment: AuthResult;
  pct?: number;
  reportUri?: string;
}

export interface AuthenticationResult {
  investigationId: string;
  spf: SPFResult;
  dkim: DKIMResult;
  dmarc: DMARCResult;
  senderPathStatus: AuthResult;
  engine: string;
}

// ---- IOC ----

export interface IOC {
  id: string;
  investigationId: string;
  indicator: string;
  type: IOCType;
  verdict: IOCVerdict;
  confidence: number; // 0-100
  firstSeen: string;
  lastSeen: string;
  source: string;
  tags: string[];
  relatedCases: string[];
  country?: string;
  asn?: string;
  organization?: string;
}

export interface IOCDetail extends IOC {
  infrastructure?: InfrastructurePoint;
  threatIntel: ThreatIntelResult[];
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
}

// ---- Attachment ----

export interface Attachment {
  id: string;
  investigationId: string;
  filename: string;
  mimeType: string;
  size: number;
  sha256: string;
  md5?: string;
  sha1?: string;
  verdict: IOCVerdict;
  analysisNotes: string[];
  macros?: boolean;
  links?: string[];
  engine: string;
}

// ---- Infrastructure ----

export interface InfrastructurePoint {
  id: string;
  investigationId: string;
  ip?: string;
  hostname?: string;
  asn?: string;
  organization?: string;
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  riskLevel: RiskLevel;
  role: 'SENDER' | 'RELAY' | 'DOMAIN_HOST' | 'REDIRECT' | 'C2' | 'UNKNOWN';
  sources: string[];
}

// ---- Threat Intelligence ----

export interface ThreatIntelResult {
  id: string;
  investigationId: string;
  indicator: string;
  source: 'VirusTotal' | 'AbuseIPDB' | 'AlienVault OTX' | 'URLhaus' | 'ThreatFox' | 'DNS' | 'RDAP';
  verdict: IOCVerdict;
  confidence: number;
  details?: Record<string, unknown>;
  lastChecked: string;
  available: boolean;
  rawResponse?: string;
}

// ---- Timeline ----

export type TimelineCategory = 'AUTHENTICATION' | 'IOC' | 'NETWORK' | 'THREAT_INTEL' | 'ANALYST' | 'SYSTEM';

export interface TimelineEvent {
  id: string;
  investigationId: string;
  timestamp: string;
  category: TimelineCategory;
  event: string;
  evidence: string;
  source: string;
  severity: RiskLevel;
}

// ---- Graph ----

export type GraphNodeType = 'EMAIL' | 'SENDER' | 'REPLY_TO' | 'DOMAIN' | 'URL' | 'IP' | 'ASN' | 'ATTACHMENT' | 'HASH';
export type GraphEdgeType = 'SENT_FROM' | 'REPLIED_TO' | 'RESOLVES_TO' | 'HOSTED_ON' | 'CONTAINS' | 'MATCHES' | 'OBSERVED_WITH';

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  data: Record<string, unknown>;
  riskLevel?: RiskLevel;
  verdict?: IOCVerdict;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: GraphEdgeType;
}

export interface InvestigationGraph {
  investigationId: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// ---- Risk ----

export interface RiskFactor {
  id: string;
  category: string;
  factor: string;
  impact: number;
  evidence: string;
  severity: RiskLevel;
}

export interface RiskBreakdown {
  authentication: { score: number; max: number };
  iocReputation: { score: number; max: number };
  infrastructureRisk: { score: number; max: number };
  urlAnalysis: { score: number; max: number };
  attachmentRisk: { score: number; max: number };
}

export interface RiskAssessment {
  investigationId: string;
  totalScore: number;
  maxScore: number;
  riskLevel: RiskLevel;
  breakdown: RiskBreakdown;
  factors: RiskFactor[];
  engine: string;
  engineVersion: string;
}

// ---- Report ----

export interface ForensicReport {
  id: string;
  investigationId: string;
  caseId: string;
  generatedAt: string;
  analyst: string;
  sections: string[];
  dataSourcesUsed: string[];
  evidenceHashes: Record<string, string>;
}

// ---- Audit Log ----

export interface AuditLog {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  caseId?: string;
  object: string;
  result: 'SUCCESS' | 'FAILURE' | 'WARNING';
  details?: string;
  ipAddress?: string;
}

// ---- System ----

export interface ServiceStatus {
  name: string;
  description: string;
  status: 'OPERATIONAL' | 'DEGRADED' | 'OFFLINE' | 'CHECKING';
  latency?: number;
  version?: string;
}

export interface SystemHealth {
  overall: 'OPERATIONAL' | 'DEGRADED' | 'OFFLINE';
  services: ServiceStatus[];
  lastChecked: string;
}

// ---- UI State ----

export interface UploadState {
  file?: File;
  sha256?: string;
  uploadedAt?: string;
  status: 'IDLE' | 'UPLOADING' | 'PROCESSING' | 'COMPLETE' | 'ERROR';
  currentStep?: string;
  error?: string;
  investigationId?: string;
}

export interface Notification {
  id: string;
  type: 'INFO' | 'SUCCESS' | 'WARNING' | 'ERROR';
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  caseId?: string;
}

export interface SearchResult {
  type: 'INVESTIGATION' | 'IOC' | 'INDICATOR';
  id: string;
  label: string;
  subLabel?: string;
  riskLevel?: RiskLevel;
  relatedCases?: string[];
}
