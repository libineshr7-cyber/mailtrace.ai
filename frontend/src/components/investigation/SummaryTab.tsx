// ============================================================
// MAILTRACE AI — Summary Tab
// Threat assessment, risk breakdown, case info, real risk factors
// ============================================================
import { useState, useEffect } from 'react';
import { Copy, CheckCircle2, AlertTriangle, ShieldCheck, ShieldAlert } from 'lucide-react';
import type { Investigation, RiskAssessment, RiskLevel } from '../../types';
import { Badge, RiskBadge } from '../ui/Badge';
import { getRiskAssessment } from '../../services/api';
import { formatDate, formatFileSize, copyToClipboard, cn } from '../../utils';
import { LoadingOverlay } from '../ui/States';

interface Props {
  investigation: Investigation;
}

function severityBorderColor(s: RiskLevel) {
  switch (s) {
    case 'CRITICAL': return 'border-l-critical';
    case 'HIGH':     return 'border-l-orange-500';
    case 'MEDIUM':   return 'border-l-warning';
    default:         return 'border-l-success';
  }
}

function severityBadgeVariant(s: RiskLevel): 'critical' | 'high' | 'medium' | 'low' {
  switch (s) {
    case 'CRITICAL': return 'critical';
    case 'HIGH':     return 'high';
    case 'MEDIUM':   return 'medium';
    default:         return 'low';
  }
}

export default function SummaryTab({ investigation }: Props) {
  const [riskData, setRiskData] = useState<RiskAssessment | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setLoading(true);
    getRiskAssessment(investigation.id)
      .then((res) => setRiskData(res))
      .catch((err) => console.error('Failed to load risk assessment', err))
      .finally(() => setLoading(false));
  }, [investigation.id]);

  const handleCopy = () => {
    copyToClipboard(investigation.fileHash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const truncatedHash = `${investigation.fileHash.slice(0, 8)}...${investigation.fileHash.slice(-8)}`;

  if (loading && !riskData) {
    return <LoadingOverlay message="Evaluating threat scoring telemetry..." />;
  }

  const breakdown = riskData?.breakdown;
  const factors = riskData?.factors || [];

  const riskBreakdownBars = breakdown ? [
    { label: 'Authentication',  score: breakdown.authentication.score,   max: breakdown.authentication.max,   colorClass: 'bg-accent-blue' },
    { label: 'IOC Reputation',  score: breakdown.iocReputation.score,    max: breakdown.iocReputation.max,    colorClass: 'bg-critical' },
    { label: 'Infrastructure',  score: breakdown.infrastructureRisk.score, max: breakdown.infrastructureRisk.max, colorClass: 'bg-critical' },
    { label: 'URL Analysis',    score: breakdown.urlAnalysis.score,      max: breakdown.urlAnalysis.max,      colorClass: 'bg-orange-400' },
    { label: 'Attachment Risk', score: breakdown.attachmentRisk.score,   max: breakdown.attachmentRisk.max,   colorClass: 'bg-warning' },
  ] : [];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      {/* LEFT COLUMN (span 2 on lg) */}
      <div className="lg:col-span-2 space-y-4">
        {/* Panel 1: Threat Assessment Findings */}
        <div className="panel">
          <div className="panel-header flex items-center justify-between">
            <div className="flex items-center gap-2">
              {investigation.riskLevel === 'CRITICAL' ? (
                <AlertTriangle size={14} className="text-critical" />
              ) : (
                <ShieldCheck size={14} className="text-success" />
              )}
              <span className={`text-sm font-semibold ${investigation.riskLevel === 'CRITICAL' ? 'text-critical' : 'text-text-primary'}`}>
                {investigation.riskLevel === 'CRITICAL' ? 'Critical Risk Detected' : 'Threat Assessment Findings'}
              </span>
            </div>
            <span className="text-2xs font-mono text-text-muted">
              {factors.length} evidence factors
            </span>
          </div>
          <div className="panel-body divide-y divide-border">
            {factors.length === 0 ? (
              <div className="p-4 text-xs text-text-muted text-center">
                No anomalous threat factors detected for this envelope.
              </div>
            ) : (
              factors.map((f) => (
                <div
                  key={f.id}
                  className={cn(
                    'border-l-2 pl-3 py-2.5',
                    severityBorderColor(f.severity),
                  )}
                >
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={severityBadgeVariant(f.severity)}
                      className="font-mono uppercase"
                      style={{ fontSize: '0.6rem' }}
                    >
                      {f.severity}
                    </Badge>
                    <span className="text-xs font-semibold text-text-primary">{f.factor}</span>
                  </div>
                  <p className="text-xs text-text-muted mt-0.5">{f.evidence}</p>
                  <p className="mt-1" style={{ fontSize: '0.65rem' }}>
                    <span className="text-text-muted">Category: </span>
                    <span className="font-mono text-text-secondary">{f.category}</span>
                  </p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Panel 2: Risk Score Breakdown */}
        {breakdown && (
          <div className="panel">
            <div className="panel-header">
              <h3 className="panel-title">Explainable Threat Risk Breakdown</h3>
            </div>
            <div className="panel-body space-y-3">
              {riskBreakdownBars.map((bar) => (
                <div key={bar.label}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-text-secondary">{bar.label}</span>
                    <span className="text-xs font-mono text-text-primary">
                      {bar.score}
                      <span className="text-text-muted">/{bar.max}</span>
                    </span>
                  </div>
                  <div className="w-full bg-bg-tertiary rounded-full h-1.5 overflow-hidden">
                    <div
                      className={cn('h-1.5 rounded-full transition-all duration-300', bar.colorClass)}
                      style={{ width: `${Math.min(100, (bar.score / bar.max) * 100)}%` }}
                    />
                  </div>
                </div>
              ))}

              {/* Total row */}
              <div className="flex items-center justify-between pt-2 border-t border-border mt-2">
                <div>
                  <p className="text-text-muted" style={{ fontSize: '0.65rem' }}>
                    Engine: {riskData.engine} v{riskData.engineVersion}
                  </p>
                </div>
                <div className="text-right flex items-center gap-2">
                  <span className={`text-lg font-bold font-mono ${investigation.riskLevel === 'CRITICAL' ? 'text-critical' : 'text-text-primary'}`}>
                    {riskData.totalScore}
                  </span>
                  <span className="text-xs text-text-muted font-mono"> / {riskData.maxScore}</span>
                  <RiskBadge level={investigation.riskLevel} />
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* RIGHT COLUMN (span 1) */}
      <div className="col-span-1 space-y-4">
        {/* Case Information */}
        <div className="panel">
          <div className="panel-header">
            <h3 className="panel-title">Case Profile</h3>
          </div>
          <div className="panel-body">
            <dl className="divide-y divide-border">
              <div className="flex items-start justify-between gap-2 py-2.5">
                <dt className="text-text-muted uppercase tracking-wider flex-shrink-0" style={{ fontSize: '0.6rem' }}>Case ID</dt>
                <dd className="text-xs text-text-primary font-medium font-mono text-right">{investigation.caseId}</dd>
              </div>

              <div className="flex items-start justify-between gap-2 py-2.5">
                <dt className="text-text-muted uppercase tracking-wider flex-shrink-0" style={{ fontSize: '0.6rem' }}>File</dt>
                <dd className="text-xs text-text-primary font-medium text-right truncate max-w-[140px] font-mono">{investigation.fileName}</dd>
              </div>

              <div className="flex items-start justify-between gap-2 py-2.5">
                <dt className="text-text-muted uppercase tracking-wider flex-shrink-0" style={{ fontSize: '0.6rem' }}>SHA-256</dt>
                <dd className="flex items-center gap-1.5">
                  <span className="text-xs text-text-primary font-mono">{truncatedHash}</span>
                  <button
                    onClick={handleCopy}
                    className="text-text-muted hover:text-text-primary transition-colors flex-shrink-0"
                    title="Copy full hash"
                  >
                    {copied
                      ? <CheckCircle2 size={12} className="text-success" />
                      : <Copy size={12} />
                    }
                  </button>
                </dd>
              </div>

              <div className="flex items-start justify-between gap-2 py-2.5">
                <dt className="text-text-muted uppercase tracking-wider flex-shrink-0" style={{ fontSize: '0.6rem' }}>File Size</dt>
                <dd className="text-xs text-text-primary font-medium font-mono">{formatFileSize(investigation.fileSize)}</dd>
              </div>

              <div className="flex items-start justify-between gap-2 py-2.5">
                <dt className="text-text-muted uppercase tracking-wider flex-shrink-0" style={{ fontSize: '0.6rem' }}>Ingested Date</dt>
                <dd className="text-xs text-text-primary font-medium text-right">{formatDate(investigation.createdAt)}</dd>
              </div>

              <div className="flex items-start justify-between gap-2 py-2.5">
                <dt className="text-text-muted uppercase tracking-wider flex-shrink-0" style={{ fontSize: '0.6rem' }}>Analysis Pipeline</dt>
                <dd className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-success flex-shrink-0" />
                  <span className="text-xs text-success font-medium">Completed</span>
                </dd>
              </div>

              <div className="flex items-start justify-between gap-2 py-2.5">
                <dt className="text-text-muted uppercase tracking-wider flex-shrink-0" style={{ fontSize: '0.6rem' }}>Analyst / Engine</dt>
                <dd className="text-xs text-text-primary font-medium">{investigation.analyst}</dd>
              </div>
            </dl>
          </div>
        </div>

        {/* Contributing Factors */}
        <div className="panel">
          <div className="panel-header">
            <h3 className="panel-title">Contributing Risk Points</h3>
          </div>
          <div className="panel-body space-y-1.5">
            {factors.length === 0 ? (
              <div className="text-xs text-text-muted py-2 text-center">Zero penalty points calculated</div>
            ) : (
              factors.map((rf) => {
                const plusColor =
                  rf.severity === 'CRITICAL' ? 'text-critical' :
                  rf.severity === 'HIGH'     ? 'text-orange-400' :
                                               'text-warning';
                return (
                  <div key={rf.id} className="flex items-start justify-between gap-2 py-1">
                    <div className="flex items-start gap-1.5 flex-1 min-w-0">
                      <span className={cn('text-xs font-bold flex-shrink-0 mt-px', plusColor)}>+</span>
                      <span className="text-xs text-text-primary leading-tight">{rf.factor}</span>
                    </div>
                    <span className={cn('text-xs font-mono font-semibold flex-shrink-0', plusColor)}>
                      +{rf.impact}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
