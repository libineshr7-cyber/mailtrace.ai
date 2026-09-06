// ============================================================
// MAILTRACE AI — API Service Layer
// Direct live connection to real-time FastAPI backend engine
// ============================================================

import type {
  Investigation, HeaderAnalysis, AuthenticationResult,
  IOC, Attachment, InfrastructurePoint, ThreatIntelResult,
  TimelineEvent, InvestigationGraph, RiskAssessment,
  AuditLog, SystemHealth, SearchResult,
} from '../types';

const RAW_BASE = (import.meta.env.VITE_API_BASE_URL || '').trim();
const BASE_URL = RAW_BASE
  ? (RAW_BASE.endsWith('/') ? `${RAW_BASE.slice(0, -1)}/api` : `${RAW_BASE}/api`)
  : '/api';

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const errorText = await res.text().catch(() => '');
    throw new Error(`API error ${res.status}: ${errorText || res.statusText}`);
  }
  return res.json();
}

// ---- Investigations ----

export async function getInvestigations(): Promise<Investigation[]> {
  return apiFetch<Investigation[]>('/investigations');
}

export async function getInvestigation(id: string): Promise<Investigation> {
  return apiFetch<Investigation>(`/investigations/${id}`);
}

// ---- Email Upload / Analysis ----

export interface AnalyzeResult {
  investigationId: string;
  caseId: string;
  logs: Array<{
    time: string;
    subsystem: string;
    message: string;
    status: 'INFO' | 'SUCCESS' | 'WARN' | 'CRIT';
  }>;
}

export async function analyzeEmail(file?: File | null, rawText?: string | null): Promise<AnalyzeResult> {
  const form = new FormData();
  if (file) {
    form.append('file', file);
  }
  if (rawText) {
    form.append('rawText', rawText);
  }

  const res = await fetch(`${BASE_URL}/analyze/email`, {
    method: 'POST',
    body: form,
  });

  if (!res.ok) {
    const err = await res.text().catch(() => '');
    throw new Error(`Analysis failed: ${err || res.statusText}`);
  }

  return res.json();
}

// ---- Headers ----

export async function getHeaders(investigationId: string): Promise<HeaderAnalysis> {
  return apiFetch<HeaderAnalysis>(`/investigations/${investigationId}/headers`);
}

// ---- Authentication ----

export async function getAuthentication(investigationId: string): Promise<AuthenticationResult> {
  return apiFetch<AuthenticationResult>(`/investigations/${investigationId}/authentication`);
}

// ---- IOCs ----

export async function getIOCs(investigationId: string): Promise<IOC[]> {
  return apiFetch<IOC[]>(`/investigations/${investigationId}/iocs`);
}

export async function getAllIOCs(): Promise<IOC[]> {
  return apiFetch<IOC[]>('/iocs');
}

// ---- Attachments ----

export async function getAttachments(investigationId: string): Promise<Attachment[]> {
  return apiFetch<Attachment[]>(`/investigations/${investigationId}/attachments`);
}

// ---- Infrastructure ----

export async function getInfrastructure(investigationId: string): Promise<InfrastructurePoint[]> {
  return apiFetch<InfrastructurePoint[]>(`/investigations/${investigationId}/infrastructure`);
}

export async function getAllInfrastructure(): Promise<InfrastructurePoint[]> {
  return apiFetch<InfrastructurePoint[]>('/infrastructure');
}

// ---- Threat Intelligence ----

export async function getThreatIntel(investigationId: string): Promise<ThreatIntelResult[]> {
  return apiFetch<ThreatIntelResult[]>(`/investigations/${investigationId}/threat-intelligence`);
}

// ---- Timeline ----

export async function getTimeline(investigationId: string): Promise<TimelineEvent[]> {
  return apiFetch<TimelineEvent[]>(`/investigations/${investigationId}/timeline`);
}

// ---- Graph ----

export async function getGraph(investigationId: string): Promise<InvestigationGraph> {
  return apiFetch<InvestigationGraph>(`/investigations/${investigationId}/graph`);
}

// ---- Risk ----

export async function getRiskAssessment(investigationId: string): Promise<RiskAssessment> {
  return apiFetch<RiskAssessment>(`/investigations/${investigationId}/risk`);
}

// ---- Overview Stats ----

export interface OverviewStats {
  activeInvestigations: number;
  criticalCases: number;
  criticalIOCs: number;
  correlatedCampaigns: number;
  threatDistribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export async function getOverviewStats(): Promise<OverviewStats> {
  return apiFetch<OverviewStats>('/overview/stats');
}

// ---- Audit Logs ----

export async function getAuditLogs(): Promise<AuditLog[]> {
  return apiFetch<AuditLog[]>('/audit-logs');
}

// ---- System Health ----

export async function getSystemHealth(): Promise<SystemHealth> {
  return apiFetch<SystemHealth>('/system/health');
}

// ---- Search ----

export async function search(query: string): Promise<SearchResult[]> {
  return apiFetch<SearchResult[]>(`/search?q=${encodeURIComponent(query)}`);
}

// ---- Quarantine / Remediation Action ----

export async function executeQuarantineAction(action: string, caseId: string, target?: string): Promise<{ status: string; message: string }> {
  return apiFetch('/quarantine/action', {
    method: 'POST',
    body: JSON.stringify({ action, caseId, target, user: 'Security Analyst' }),
  });
}

// ---- Sample Emails ----

export interface SampleEmail {
  filename: string;
  size: number;
  content: string;
}

export async function getSampleEmails(): Promise<SampleEmail[]> {
  return apiFetch<SampleEmail[]>('/samples');
}
