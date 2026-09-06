// ============================================================
// MAILTRACE AI — Utility helpers
// ============================================================

import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { RiskLevel, AuthResult, IOCVerdict, CaseStatus } from '../types';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false,
    timeZone: 'Asia/Kolkata',
  }) + ' IST';
}

export function formatDateShort(iso: string): string {
  return new Date(iso).toLocaleDateString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric',
  });
}

export function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString('en-IN', {
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
}

export function formatRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

export function truncateHash(hash: string, len = 8): string {
  if (hash.length <= len * 2 + 4) return hash;
  return `${hash.slice(0, len)}...${hash.slice(-4)}`;
}

export function truncateMiddle(str: string, maxLen = 48): string {
  if (str.length <= maxLen) return str;
  const half = Math.floor((maxLen - 3) / 2);
  return `${str.slice(0, half)}...${str.slice(-half)}`;
}

export function riskColor(level: RiskLevel): string {
  switch (level) {
    case 'CRITICAL': return 'text-critical';
    case 'HIGH':     return 'text-orange-400';
    case 'MEDIUM':   return 'text-warning';
    case 'LOW':      return 'text-success';
    default:         return 'text-text-muted';
  }
}

export function riskBgColor(level: RiskLevel): string {
  switch (level) {
    case 'CRITICAL': return 'bg-critical-muted border-critical-border text-critical';
    case 'HIGH':     return 'bg-orange-950 border-orange-900 text-orange-400';
    case 'MEDIUM':   return 'bg-warning-muted border-warning-border text-warning';
    case 'LOW':      return 'bg-success-muted border-success-border text-success';
    default:         return 'bg-bg-tertiary border-border text-text-muted';
  }
}

export function authColor(result: AuthResult): string {
  switch (result) {
    case 'PASS':        return 'text-success';
    case 'FAIL':        return 'text-critical';
    case 'PARTIAL':     return 'text-warning';
    case 'SUSPICIOUS':  return 'text-warning';
    default:            return 'text-text-muted';
  }
}

export function verdictColor(v: IOCVerdict): string {
  switch (v) {
    case 'MALICIOUS':   return 'text-critical';
    case 'SUSPICIOUS':  return 'text-warning';
    case 'CLEAN':       return 'text-success';
    default:            return 'text-text-muted';
  }
}

export function statusColor(s: CaseStatus): string {
  switch (s) {
    case 'NEW':          return 'bg-info-muted border-accent-blue-muted text-accent-blue';
    case 'INVESTIGATING': return 'bg-warning-muted border-warning-border text-warning';
    case 'CONTAINED':    return 'bg-orange-950 border-orange-900 text-orange-400';
    case 'RESOLVED':     return 'bg-success-muted border-success-border text-success';
    case 'ARCHIVED':     return 'bg-bg-tertiary border-border text-text-muted';
  }
}

export function copyToClipboard(text: string): void {
  navigator.clipboard.writeText(text).catch(() => {
    const el = document.createElement('textarea');
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
  });
}
