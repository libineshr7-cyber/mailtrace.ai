// ============================================================
// MAILTRACE AI — HeadersTab
// Forensic email header viewer with received-chain analysis
// ============================================================

import { useState, useEffect } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Copy,
  AlertTriangle,
  CheckCircle2,
  Server,
  MapPin,
  Clock,
  ArrowDown,
} from 'lucide-react';
import type { HeaderAnalysis } from '../../types';
import { getHeaders } from '../../services/api';
import { copyToClipboard, formatTime, cn } from '../../utils';
import { LoadingOverlay, ErrorState } from '../ui/States';

interface SectionProps {
  title: string;
  defaultOpen?: boolean;
  rightSlot?: React.ReactNode;
  children: React.ReactNode;
}

function Section({ title, defaultOpen = true, rightSlot, children }: SectionProps) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="panel mb-4">
      <button
        onClick={() => setOpen(o => !o)}
        className="panel-header w-full text-left hover:bg-bg-hover transition-colors"
      >
        <span className="text-xs font-semibold text-text-primary uppercase tracking-wider">
          {title}
        </span>
        <div className="flex items-center gap-2">
          {rightSlot}
          {open
            ? <ChevronUp size={14} className="text-text-muted" />
            : <ChevronDown size={14} className="text-text-muted" />}
        </div>
      </button>
      {open && <div>{children}</div>}
    </div>
  );
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handle = () => {
    copyToClipboard(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button
      onClick={handle}
      title="Copy value"
      className={cn(
        'p-1 rounded transition-colors',
        copied
          ? 'text-success'
          : 'text-text-muted hover:text-text-primary hover:bg-bg-tertiary',
      )}
    >
      {copied ? <CheckCircle2 size={12} /> : <Copy size={12} />}
    </button>
  );
}

function KVRow({ label, value, mono = true }: { label: string; value?: string; mono?: boolean }) {
  if (!value) return null;
  return (
    <div className="flex gap-2 items-start min-w-0">
      <span className="text-2xs text-text-muted w-16 shrink-0 pt-px">{label}</span>
      <span className={`text-2xs text-text-primary break-all ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  );
}

interface Props {
  investigationId: string;
}

export default function HeadersTab({ investigationId }: Props) {
  const [headerData, setHeaderData] = useState<HeaderAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = () => {
    setLoading(true);
    setError(null);
    getHeaders(investigationId)
      .then(data => setHeaderData(data))
      .catch(err => setError(err.message || 'Failed to load headers'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, [investigationId]);

  if (loading) return <LoadingOverlay message="Parsing RFC 5322 headers and hop trace..." />;
  if (error || !headerData) return <ErrorState message={error || 'No headers found for this investigation'} retry={loadData} />;

  const suspiciousCount = headerData.rawHeaders.filter(h => h.isSuspicious).length;
  const authResultsHeader = headerData.rawHeaders.find(
    h => h.name.toLowerCase() === 'authentication-results',
  );

  return (
    <div>
      {/* Top stats pills */}
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <div className="bg-bg-tertiary border border-border px-3 py-1.5 rounded text-xs flex items-center gap-1.5">
          <span className="text-text-muted">Total Headers</span>
          <span className="font-mono font-semibold text-text-primary">{headerData.rawHeaders.length}</span>
        </div>
        <div className="bg-bg-tertiary border border-border px-3 py-1.5 rounded text-xs flex items-center gap-1.5">
          <span className="text-text-muted">Suspicious</span>
          <span className={`font-mono font-semibold ${suspiciousCount > 0 ? 'text-warning' : 'text-success'}`}>
            {suspiciousCount}
          </span>
        </div>
        <div className="bg-bg-tertiary border border-border px-3 py-1.5 rounded text-xs flex items-center gap-1.5">
          <span className="text-text-muted">Received Hops</span>
          <span className="font-mono font-semibold text-text-primary">{headerData.receivedChain.length}</span>
        </div>
      </div>

      {/* Section 1: Raw Email Headers */}
      <Section
        title="Email Headers"
        defaultOpen
        rightSlot={
          <span className="text-2xs text-text-muted font-mono">
            {headerData.rawHeaders.length} headers
          </span>
        }
      >
        <div className="divide-y divide-border max-h-[500px] overflow-y-auto">
          {headerData.rawHeaders.map((header, idx) => (
            <div
              key={`${header.name}-${idx}`}
              className={`flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-3 px-3 sm:px-4 py-2.5 ${header.isSuspicious ? 'border-l-2 border-warning' : ''}`}
              style={header.isSuspicious ? { backgroundColor: 'rgba(47, 33, 8, 0.25)' } : {}}
            >
              <div className="w-full sm:w-48 shrink-0 pt-px flex items-center justify-between">
                <span className="font-mono text-xs font-semibold text-text-muted">{header.name}</span>
                <div className="sm:hidden flex items-center gap-1">
                  {header.isSuspicious && (
                    <span className="badge border bg-warning-muted border-warning-border text-warning text-2xs">
                      Suspicious
                    </span>
                  )}
                  <CopyBtn text={`${header.name}: ${header.value}`} />
                </div>
              </div>
              <div className="flex-1 min-w-0">
                <span className="font-mono text-xs text-text-primary break-all">{header.value}</span>
                {header.notes && (
                  <p className="text-2xs text-text-muted mt-0.5 italic">{header.notes}</p>
                )}
              </div>
              <div className="hidden sm:flex items-center gap-2 shrink-0">
                {header.isSuspicious && (
                  <div className="flex items-center gap-1 shrink-0 pt-px">
                    <AlertTriangle size={12} className="text-warning" />
                    <span className="badge border bg-warning-muted border-warning-border text-warning">
                      Suspicious
                    </span>
                  </div>
                )}
                <CopyBtn text={`${header.name}: ${header.value}`} />
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Section 2: Received Chain */}
      {headerData.receivedChain.length > 0 && (
        <Section
          title="Received Chain"
          defaultOpen
          rightSlot={
            <span className="text-2xs text-text-muted font-mono">
              {headerData.receivedChain.length} hops
            </span>
          }
        >
          <div className="p-4">
            {headerData.receivedChain.map((hop, idx) => (
              <div key={hop.hopIndex}>
                <div
                  className={`panel ${hop.isSuspicious ? 'border-l-4 border-l-warning' : 'border-l-4 border-l-border'}`}
                >
                  <div className="panel-header py-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={`inline-flex items-center justify-center w-5 h-5 rounded-full text-2xs font-bold font-mono border ${hop.isSuspicious ? 'bg-warning-muted border-warning-border text-warning' : 'bg-bg-tertiary border-border text-text-muted'}`}
                      >
                        {hop.hopIndex}
                      </span>
                      <span className="text-xs font-semibold text-text-primary">
                        Hop {hop.hopIndex}
                      </span>
                      {hop.isSuspicious && (
                        <div className="flex items-center gap-1">
                          <AlertTriangle size={11} className="text-warning" />
                          <span className="text-2xs text-warning font-medium">Suspicious hop</span>
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 text-2xs text-text-muted font-mono">
                      <Clock size={11} />
                      {formatTime(hop.timestamp)}
                      {hop.delaySeconds !== undefined && hop.delaySeconds > 0 && (
                        <span className="text-text-muted ml-1">+{hop.delaySeconds}s</span>
                      )}
                    </div>
                  </div>
                  <div className="panel-body py-3 grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5">
                    <div className="space-y-1.5">
                      <KVRow label="From" value={hop.from} />
                      <KVRow label="By" value={hop.by} />
                      <KVRow label="With" value={hop.with} />
                    </div>
                    <div className="space-y-1.5">
                      {hop.ip && (
                        <div className="flex items-center gap-1.5">
                          <Server size={11} className="text-text-muted shrink-0" />
                          <span className="font-mono text-2xs text-text-primary">{hop.ip}</span>
                          {hop.hostname && hop.hostname !== hop.ip && (
                            <span className="text-2xs text-text-muted">({hop.hostname})</span>
                          )}
                        </div>
                      )}
                      {(hop.country || hop.city) && (
                        <div className="flex items-center gap-1.5">
                          <MapPin size={11} className="text-text-muted shrink-0" />
                          <span className="text-2xs text-text-secondary">
                            {[hop.city, hop.country].filter(Boolean).join(', ')}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                {idx < headerData.receivedChain.length - 1 && (
                  <div className="flex flex-col items-center my-0.5">
                    <div className="w-px h-3 border-l border-dashed border-border" />
                    <ArrowDown size={12} className="text-text-muted" />
                    <div className="w-px h-3 border-l border-dashed border-border" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Section 3: Authentication Results Header */}
      {authResultsHeader && (
        <Section
          title="Authentication Results"
          defaultOpen={false}
          rightSlot={
            <span className="badge border bg-bg-tertiary border-border text-text-muted">
              Raw Header
            </span>
          }
        >
          <div className="p-4">
            <div className="relative">
              <pre className="font-mono text-xs text-text-secondary bg-bg-primary border border-border rounded p-3 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                {authResultsHeader.value}
              </pre>
              <div className="absolute top-2 right-2">
                <CopyBtn text={authResultsHeader.value} />
              </div>
            </div>
          </div>
        </Section>
      )}

      {/* Section 4: Forged Fields Warning */}
      {headerData.forgedFields && headerData.forgedFields.length > 0 && (
        <div className="panel border border-warning-border mb-4" style={{ backgroundColor: 'rgba(47, 33, 8, 0.3)' }}>
          <div className="panel-header py-2.5" style={{ borderBottom: '1px solid rgba(90, 62, 10, 0.4)' }}>
            <div className="flex items-center gap-2">
              <AlertTriangle size={14} className="text-warning" />
              <span className="text-xs font-semibold text-warning">
                Potentially Forged Fields Detected
              </span>
            </div>
            <span className="badge border bg-warning-muted border-warning-border text-warning">
              {headerData.forgedFields.length} field{headerData.forgedFields.length > 1 ? 's' : ''}
            </span>
          </div>
          <div className="panel-body py-3">
            <p className="text-xs text-text-muted mb-2">
              The following header fields appear inconsistent with the originating infrastructure
              and may have been manipulated by the sender:
            </p>
            <ul className="space-y-1">
              {headerData.forgedFields.map(field => (
                <li key={field} className="flex items-center gap-2">
                  <AlertTriangle size={11} className="text-warning shrink-0" />
                  <span className="font-mono text-xs text-warning font-medium">{field}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
