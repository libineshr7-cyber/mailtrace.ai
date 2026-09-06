// ============================================================
// MAILTRACE AI — Attachments Analysis Tab
// Static analysis, file hashing, embedded link extraction
// ============================================================
import { useState, useEffect } from 'react';
import {
  FileText, Copy, AlertTriangle, Shield, CheckCircle2,
  ExternalLink, Hash, Info, FileCode, Layers
} from 'lucide-react';
import { getAttachments } from '../../services/api';
import type { Attachment } from '../../types';
import { VerdictBadge, Badge } from '../ui/Badge';
import { LoadingOverlay, ErrorState, EmptyState } from '../ui/States';
import { formatFileSize, truncateHash, copyToClipboard } from '../../utils';

interface Props {
  investigationId: string;
}

export default function AttachmentsTab({ investigationId }: Props) {
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const loadAttachments = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await getAttachments(investigationId);
      setAttachments(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load attachments');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAttachments();
  }, [investigationId]);

  if (loading) return <LoadingOverlay message="Performing static file analysis..." />;
  if (error) return <ErrorState message={error} retry={loadAttachments} />;

  if (attachments.length === 0) {
    return (
      <div className="panel p-6">
        <EmptyState
          title="No attachments detected"
          description="The inspected MIME envelope contains no attached binary or document payloads."
        />
      </div>
    );
  }

  const handleCopy = (val: string, key: string) => {
    copyToClipboard(val);
    setCopiedHash(key);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-4">
      {attachments.map((att) => (
        <div
          key={att.id}
          className={`panel border-l-4 ${
            att.verdict === 'MALICIOUS'
              ? 'border-l-critical'
              : att.verdict === 'SUSPICIOUS'
              ? 'border-l-warning'
              : 'border-l-success'
          }`}
        >
          {/* Header */}
          <div className="panel-header bg-bg-tertiary flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <div className="flex items-center gap-3">
              <FileText className="w-5 h-5 text-accent-blue flex-shrink-0" />
              <div>
                <div className="text-sm font-bold text-text-primary font-mono">{att.filename}</div>
                <div className="text-2xs text-text-muted mt-0.5">
                  MIME Content-Type: <span className="font-mono text-text-secondary">{att.mimeType}</span> · Size: {formatFileSize(att.size)}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <VerdictBadge verdict={att.verdict} />
            </div>
          </div>

          <div className="panel-body space-y-4">
            {/* Cryptographic Hashes Grid */}
            <div>
              <span className="section-title text-2xs mb-2 block">Cryptographic Hashes</span>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {/* SHA-256 */}
                <div className="p-2.5 bg-bg-tertiary border border-border rounded">
                  <div className="flex items-center justify-between text-2xs text-text-muted mb-1">
                    <span className="font-semibold">SHA-256</span>
                    <button
                      onClick={() => handleCopy(att.sha256, 'sha256')}
                      className="text-text-muted hover:text-text-primary flex items-center gap-1"
                    >
                      <Copy size={10} />
                      {copiedHash === 'sha256' ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="font-mono text-2xs text-text-primary break-all">
                    {att.sha256}
                  </div>
                </div>

                {/* MD5 */}
                {att.md5 && (
                  <div className="p-2.5 bg-bg-tertiary border border-border rounded">
                    <div className="flex items-center justify-between text-2xs text-text-muted mb-1">
                      <span className="font-semibold">MD5</span>
                      <button
                        onClick={() => handleCopy(att.md5!, 'md5')}
                        className="text-text-muted hover:text-text-primary flex items-center gap-1"
                      >
                        <Copy size={10} />
                        {copiedHash === 'md5' ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <div className="font-mono text-2xs text-text-primary break-all">
                      {att.md5}
                    </div>
                  </div>
                )}

                {/* SHA-1 */}
                {att.sha1 && (
                  <div className="p-2.5 bg-bg-tertiary border border-border rounded">
                    <div className="flex items-center justify-between text-2xs text-text-muted mb-1">
                      <span className="font-semibold">SHA-1</span>
                      <button
                        onClick={() => handleCopy(att.sha1!, 'sha1')}
                        className="text-text-muted hover:text-text-primary flex items-center gap-1"
                      >
                        <Copy size={10} />
                        {copiedHash === 'sha1' ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <div className="font-mono text-2xs text-text-primary break-all">
                      {att.sha1}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Static Analysis Findings */}
            <div>
              <span className="section-title text-2xs mb-2 block">Static Inspection Findings</span>
              <div className="border border-border rounded divide-y divide-border bg-bg-tertiary">
                {att.analysisNotes.map((note, idx) => (
                  <div key={idx} className="p-2.5 flex items-start gap-2.5 text-xs">
                    <AlertTriangle className="w-3.5 h-3.5 text-warning flex-shrink-0 mt-0.5" />
                    <span className="text-text-primary">{note}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Embedded URLs */}
            {att.links && att.links.length > 0 && (
              <div>
                <span className="section-title text-2xs mb-2 block">Embedded URLs Extracted</span>
                <div className="border border-critical-border bg-critical-muted rounded divide-y divide-critical-border">
                  {att.links.map((link, idx) => (
                    <div key={idx} className="p-2.5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs font-mono text-critical break-all">
                      <div className="flex items-center gap-2">
                        <ExternalLink size={12} className="flex-shrink-0 text-critical" />
                        <span>{link}</span>
                      </div>
                      <span className="badge bg-critical-muted text-critical border border-critical-border text-2xs uppercase shrink-0">
                        MALICIOUS TARGET
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Technical Verification Attribution & Sandbox Disclaimer */}
            <div className="p-3 bg-bg-primary border border-border rounded text-2xs text-text-muted space-y-1">
              <div className="flex items-center gap-1.5 text-text-secondary font-medium">
                <Info size={12} className="text-accent-blue" />
                <span>Forensic Static Analysis Methodology</span>
              </div>
              <p className="leading-relaxed">
                These findings represent static MIME byte analysis, structural PDF parser inspection, and embedded object extraction conducted by the <span className="font-mono text-text-secondary">{att.engine}</span>. No dynamic sandbox execution or payload detonation was performed in this environment.
              </p>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
