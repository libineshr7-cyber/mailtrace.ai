// ============================================================
// MAILTRACE AI — Shared Badge Components
// ============================================================
import React from 'react';
import { cn, riskBgColor, statusColor } from '../../utils';
import type { RiskLevel, AuthResult, IOCVerdict, CaseStatus } from '../../types';

interface BadgeProps {
  className?: string;
  children: React.ReactNode;
  style?: React.CSSProperties;
}

// Risk badges
export function RiskBadge({ level, className }: { level: RiskLevel; className?: string }) {
  return (
    <span className={cn('badge border', riskBgColor(level), className)}>
      {level}
    </span>
  );
}

// Auth result badges
const AUTH_STYLES: Record<AuthResult, string> = {
  PASS:       'bg-success-muted border-success-border text-success',
  FAIL:       'bg-critical-muted border-critical-border text-critical',
  PARTIAL:    'bg-warning-muted border-warning-border text-warning',
  SUSPICIOUS: 'bg-warning-muted border-warning-border text-warning',
  UNKNOWN:    'bg-bg-tertiary border-border text-text-muted',
};

export function AuthBadge({ result, className }: { result: AuthResult; className?: string }) {
  return (
    <span className={cn('badge border', AUTH_STYLES[result], className)}>
      {result}
    </span>
  );
}

// Verdict badges
const VERDICT_STYLES: Record<IOCVerdict, string> = {
  MALICIOUS:  'bg-critical-muted border-critical-border text-critical',
  SUSPICIOUS: 'bg-warning-muted border-warning-border text-warning',
  CLEAN:      'bg-success-muted border-success-border text-success',
  UNKNOWN:    'bg-bg-tertiary border-border text-text-muted',
};

export function VerdictBadge({ verdict, className }: { verdict: IOCVerdict; className?: string }) {
  return (
    <span className={cn('badge border', VERDICT_STYLES[verdict], className)}>
      {verdict}
    </span>
  );
}

// Case status badges
export function StatusBadge({ status, className }: { status: CaseStatus; className?: string }) {
  return (
    <span className={cn('badge border', statusColor(status), className)}>
      {status}
    </span>
  );
}

// Generic semantic badge
export function Badge({ children, variant = 'neutral', className, style }: BadgeProps & {
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'neutral' | 'pass' | 'fail' | 'suspicious';
}) {
  const styles = {
    critical:   'bg-critical-muted border-critical-border text-critical',
    high:       'bg-orange-950 border-orange-900 text-orange-400',
    medium:     'bg-warning-muted border-warning-border text-warning',
    low:        'bg-success-muted border-success-border text-success',
    info:       'bg-info-muted border-accent-blue-muted text-accent-blue',
    neutral:    'bg-bg-tertiary border-border text-text-secondary',
    pass:       'bg-success-muted border-success-border text-success',
    fail:       'bg-critical-muted border-critical-border text-critical',
    suspicious: 'bg-warning-muted border-warning-border text-warning',
  };
  return (
    <span className={cn('badge border', styles[variant], className)} style={style}>
      {children}
    </span>
  );
}
