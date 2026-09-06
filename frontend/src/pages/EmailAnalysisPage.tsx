// ============================================================
// MAILTRACE AI — Email Analysis & Ingestion Console
// Enterprise MIME inspection, cryptographic verification, IOC extraction
// ============================================================
import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileUp, FileText, CheckCircle2, AlertTriangle, Hash, Clock,
  ArrowRight, Shield, Play, Terminal, ShieldCheck, FileCode,
  Copy, Check, RefreshCw, X, HardDrive, Cpu, Lock, Sparkles
} from 'lucide-react';
import { formatFileSize, truncateHash, formatDate, copyToClipboard } from '../utils';
import { analyzeEmail, getInvestigations, getSampleEmails, type SampleEmail } from '../services/api';
import type { Investigation } from '../types';

type IngestMode = 'FILE' | 'RAW_TEXT';
type IngestStatus = 'IDLE' | 'ANALYZING' | 'COMPLETED';

interface IngressFile {
  name: string;
  size: number;
  sha256: string;
  uploadedAt: string;
  mimeType: string;
  rawFile?: File;
  rawContent?: string;
}

interface LogEntry {
  time: string;
  subsystem: string;
  message: string;
  status: 'INFO' | 'SUCCESS' | 'WARN' | 'CRIT';
}

const DEFAULT_SAMPLE_RFC = `From: "Accounts Billing" <billing@secure-payments.example>
To: "Finance Operations" <finance@company.internal>
Date: Fri, 04 Sep 2026 14:22:18 +0000
Subject: Urgent Invoice Payment Required - INV-2026-8891
Message-ID: <20260904142218.8891@secure-payments.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_NextPart_000_188416"
Received: from mail-relay.secure-payments.example (mail-relay.secure-payments.example [185.220.101.47])
    by mx.company.internal (MailTrace Ingress Gateway) with ESMTP id MT882190
    for <finance@company.internal>; Fri, 04 Sep 2026 14:23:42 +0000
Authentication-Results: mx.company.internal;
    spf=fail (domain secure-payments.example does not designate 185.220.101.47) smtp.mailfrom=billing@secure-payments.example;
    dkim=pass (2048-bit key) header.d=secure-payments.example header.s=20230630;
    dmarc=fail (p=reject dis=quarantine) header.from=secure-payments.example;

This is a multi-part message in MIME format.
------=_NextPart_000_188416
Content-Type: text/plain; charset="utf-8"

Please process the attached overdue invoice immediately to avoid service disruption.
Direct wire portal: http://verify-secure-portal.nl/update

------=_NextPart_000_188416
Content-Type: application/pdf; name="Invoice_INV-2026-8891.pdf"
Content-Disposition: attachment; filename="Invoice_INV-2026-8891.pdf"

[Binary Payload Omitted - Base64 Encoded Stream]
------=_NextPart_000_188416--`;

export default function EmailAnalysisPage() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<IngestMode>('FILE');
  const [status, setStatus] = useState<IngestStatus>('IDLE');
  const [selectedFile, setSelectedFile] = useState<IngressFile | null>(null);
  const [rawText, setRawText] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logProgress, setLogProgress] = useState(0);
  const [recentCases, setRecentCases] = useState<Investigation[]>([]);
  const [samples, setSamples] = useState<SampleEmail[]>([]);
  const [resultInvId, setResultInvId] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const terminalBottomRef = useRef<HTMLDivElement>(null);

  // Load recent cases and samples from API
  useEffect(() => {
    getInvestigations()
      .then((cases) => setRecentCases(cases.slice(0, 5)))
      .catch(() => {});

    getSampleEmails()
      .then((s) => setSamples(s))
      .catch(() => {});
  }, []);

  // Auto-scroll terminal during analysis
  useEffect(() => {
    if (status === 'ANALYZING') {
      terminalBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, status]);

  const computeSHA256 = async (buffer: ArrayBuffer): Promise<string> => {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  };

  const processFile = useCallback(async (file: File) => {
    setError(null);
    const ext = file.name.toLowerCase();
    if (!ext.endsWith('.eml') && !ext.endsWith('.msg') && !ext.endsWith('.txt')) {
      setError('Invalid format. MailTrace Ingress supports RFC 822 / RFC 5322 (.eml) or Outlook (.msg) files.');
      return;
    }
    if (file.size > 50 * 1024 * 1024) {
      setError('File exceeds 50 MB threshold. For oversized archives, contact SOC engineering.');
      return;
    }
    try {
      const buffer = await file.arrayBuffer();
      const sha256 = await computeSHA256(buffer);
      setSelectedFile({
        name: file.name,
        size: file.size,
        sha256,
        uploadedAt: new Date().toISOString(),
        mimeType: file.type || 'message/rfc822',
        rawFile: file,
      });
    } catch {
      setError('Cryptographic hashing calculation failed.');
    }
  }, []);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) processFile(file);
    e.target.value = '';
  }, [processFile]);

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback(() => setIsDragging(false), []);

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) processFile(file);
  }, [processFile]);

  const handleRawTextSubmit = async () => {
    if (!rawText.trim()) {
      setError('Please paste RFC 822 email headers or a MIME stream into the input area.');
      return;
    }
    setError(null);
    try {
      const encoder = new TextEncoder();
      const buffer = encoder.encode(rawText).buffer;
      const sha256 = await computeSHA256(buffer);
      setSelectedFile({
        name: 'raw_rfc822_stream.eml',
        size: buffer.byteLength,
        sha256,
        uploadedAt: new Date().toISOString(),
        mimeType: 'message/rfc822',
        rawContent: rawText,
      });
    } catch {
      setError('Failed to process raw MIME stream.');
    }
  };

  const handleCopyHash = (h: string) => {
    copyToClipboard(h);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const loadSample = (sample: SampleEmail) => {
    setMode('RAW_TEXT');
    setRawText(sample.content);
    setError(null);
  };

  const runAnalysis = async () => {
    if (!selectedFile) return;
    setStatus('ANALYZING');
    setLogs([]);
    setLogProgress(5);

    try {
      // Execute live backend analysis
      const result = await analyzeEmail(selectedFile.rawFile || null, selectedFile.rawContent || null);
      setResultInvId(result.investigationId);

      const returnedLogs = result.logs || [];
      const totalSteps = returnedLogs.length;

      if (totalSteps === 0) {
        setLogs([
          { time: '00:00.010', subsystem: 'INGRESS', message: 'Analysis complete. Case dossier initialized.', status: 'SUCCESS' }
        ]);
        setLogProgress(100);
        setStatus('COMPLETED');
        setTimeout(() => navigate(`/investigation/${result.investigationId}`), 700);
        return;
      }

      // Step through backend logs smoothly
      returnedLogs.forEach((logItem, idx) => {
        setTimeout(() => {
          setLogs((prev) => [...prev, logItem as LogEntry]);
          const pct = Math.round(((idx + 1) / totalSteps) * 100);
          setLogProgress(pct);

          if (idx === totalSteps - 1) {
            setStatus('COMPLETED');
            setTimeout(() => {
              navigate(`/investigation/${result.investigationId}`);
            }, 900);
          }
        }, (idx + 1) * 180);
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed. Ensure the MailTrace backend service is running.');
      setStatus('IDLE');
    }
  };

  // RENDER: Running Real-Time Forensic Terminal
  if (status === 'ANALYZING' || status === 'COMPLETED') {
    return (
      <div className="p-3 sm:p-6 space-y-4 max-w-4xl mx-auto">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
          <div>
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-accent-blue" />
              <h1 className="text-sm sm:text-base font-semibold text-text-primary">
                Live Forensic Ingress Engine Execution
              </h1>
            </div>
            <p className="text-2xs sm:text-xs text-text-muted mt-0.5 font-mono">
              Target: {selectedFile?.name} · SHA-256: {selectedFile?.sha256.slice(0, 16)}...
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="badge bg-bg-tertiary border border-border text-text-secondary text-2xs font-mono">
              RFC 5322 ENGINE
            </span>
            {status === 'COMPLETED' && resultInvId && (
              <button
                onClick={() => navigate(`/investigation/${resultInvId}`)}
                className="btn-primary text-xs py-1 px-3 flex items-center gap-1.5"
              >
                <span>Open Case Dossier</span>
                <ArrowRight size={12} />
              </button>
            )}
          </div>
        </div>

        {/* Diagnostic Terminal View */}
        <div className="panel bg-[#090d13] border border-border rounded overflow-hidden shadow-2xl font-mono text-xs">
          <div className="bg-[#121820] px-4 py-2 border-b border-border flex items-center justify-between text-2xs text-text-muted">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-critical inline-block" />
              <span className="w-2.5 h-2.5 rounded-full bg-warning inline-block" />
              <span className="w-2.5 h-2.5 rounded-full bg-success inline-block" />
              <span className="ml-2 text-text-secondary font-semibold">mailtrace-ingress-live-worker</span>
            </div>
            <span>PROGRESS: {logProgress}%</span>
          </div>

          <div className="p-4 space-y-1.5 min-h-[320px] max-h-[460px] overflow-y-auto leading-relaxed">
            <div className="text-text-muted text-2xs"># MailTrace AI Ingress Subsystem · Real-Time Execution Active</div>
            {logs.map((entry, idx) => (
              <div key={idx} className="flex items-start gap-2.5">
                <span className="text-text-muted text-2xs select-none">[{entry.time}]</span>
                <span
                  className={`text-2xs font-bold px-1 py-0.2 rounded ${
                    entry.status === 'CRIT'
                      ? 'bg-critical-muted text-critical border border-critical-border'
                      : entry.status === 'WARN'
                      ? 'bg-warning-muted text-warning border border-warning-border'
                      : entry.status === 'SUCCESS'
                      ? 'bg-success-muted text-success border border-success-border'
                      : 'bg-bg-tertiary text-accent-blue border border-border'
                  }`}
                >
                  {entry.subsystem}
                </span>
                <span
                  className={
                    entry.status === 'CRIT'
                      ? 'text-critical font-medium'
                      : entry.status === 'WARN'
                      ? 'text-warning'
                      : entry.status === 'SUCCESS'
                      ? 'text-success font-semibold'
                      : 'text-text-secondary'
                  }
                >
                  {entry.message}
                </span>
              </div>
            ))}
            <div ref={terminalBottomRef} />
          </div>

          {/* Progress Strip */}
          <div className="bg-[#121820] px-4 py-2 border-t border-border flex items-center justify-between text-2xs text-text-muted">
            <div className="flex items-center gap-2 w-2/3">
              <div className="w-full bg-bg-primary h-1.5 rounded-full overflow-hidden">
                <div
                  className="bg-accent-blue h-full transition-all duration-200 ease-out"
                  style={{ width: `${logProgress}%` }}
                />
              </div>
              <span className="font-mono">{logProgress}%</span>
            </div>
            <span>
              {status === 'COMPLETED'
                ? 'Analysis complete. Loading dossier...'
                : 'Executing live protocol validation & threat lookups...'}
            </span>
          </div>
        </div>
      </div>
    );
  }

  // RENDER: Clean Ingress Workstation
  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-base sm:text-lg font-semibold text-text-primary">Email Forensic Scanner</h1>
        <p className="text-xs sm:text-sm text-text-muted mt-0.5">
          Ingest raw MIME email artifacts (.eml / .msg) for cryptographic verification, hop-by-hop tracking, and deep IOC extraction
        </p>
      </div>

      <input
        ref={inputRef}
        type="file"
        accept=".eml,.msg,.txt"
        className="hidden"
        onChange={handleFileSelect}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left Column (2 Cols): Ingress Selector & Configuration */}
        <div className="lg:col-span-2 space-y-4">
          <div className="panel">
            {/* Mode Switcher Header */}
            <div className="panel-header bg-bg-tertiary flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => { setMode('FILE'); setError(null); }}
                  className={`px-3 py-1 text-xs rounded font-medium transition-colors ${
                    mode === 'FILE'
                      ? 'bg-accent-blue-muted text-accent-blue-light border border-accent-blue'
                      : 'bg-bg-secondary text-text-secondary border border-border hover:text-text-primary'
                  }`}
                >
                  Upload Email File (.eml / .msg)
                </button>
                <button
                  type="button"
                  onClick={() => { setMode('RAW_TEXT'); setError(null); }}
                  className={`px-3 py-1 text-xs rounded font-medium transition-colors ${
                    mode === 'RAW_TEXT'
                      ? 'bg-accent-blue-muted text-accent-blue-light border border-accent-blue'
                      : 'bg-bg-secondary text-text-secondary border border-border hover:text-text-primary'
                  }`}
                >
                  Paste Raw RFC 822 Stream
                </button>
              </div>
              <span className="badge bg-bg-secondary border border-border text-text-muted text-2xs font-mono">
                RFC 5322 / MIME
              </span>
            </div>

            <div className="panel-body space-y-4">
              {/* MODE 1: FILE INGESTION */}
              {mode === 'FILE' && (
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  onClick={!selectedFile ? () => inputRef.current?.click() : undefined}
                  className={`border border-dashed rounded p-6 sm:p-8 flex flex-col items-center justify-center transition-colors ${
                    selectedFile
                      ? 'border-accent-blue bg-bg-secondary cursor-default'
                      : isDragging
                      ? 'border-accent-blue bg-info-muted cursor-pointer'
                      : 'border-border hover:border-accent-blue bg-bg-secondary cursor-pointer'
                  }`}
                >
                  {!selectedFile ? (
                    <div className="text-center space-y-3">
                      <div className="w-10 h-10 mx-auto rounded border border-border bg-bg-tertiary flex items-center justify-center text-text-secondary">
                        <FileUp size={18} />
                      </div>
                      <div>
                        <div className="text-xs sm:text-sm font-semibold text-text-primary">
                          Drop raw email file here, or browse local filesystem
                        </div>
                        <div className="text-2xs text-text-muted mt-1 font-mono">
                          Accepts RFC 822 / RFC 5322 (.eml), Outlook (.msg), or plaintext envelope streams
                        </div>
                      </div>
                      <div className="pt-1">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            inputRef.current?.click();
                          }}
                          className="btn-secondary text-xs px-4 py-1.5"
                        >
                          Select File from Workstation
                        </button>
                      </div>
                      <div className="text-2xs text-text-muted">
                        Max payload: 50 MB · FIPS 180-4 SHA-256 hash calculated in real time
                      </div>
                    </div>
                  ) : (
                    /* Selected File Profile */
                    <div className="w-full space-y-3.5">
                      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2 pb-3 border-b border-border">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded bg-bg-tertiary border border-border flex items-center justify-center text-accent-blue flex-shrink-0">
                            <FileText size={18} />
                          </div>
                          <div>
                            <div className="text-sm font-bold text-text-primary font-mono break-all">
                              {selectedFile.name}
                            </div>
                            <div className="text-2xs text-text-muted mt-0.5">
                              Size: {formatFileSize(selectedFile.size)} ({selectedFile.size} bytes) · Format: {selectedFile.mimeType}
                            </div>
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedFile(null);
                            setError(null);
                          }}
                          className="btn-ghost text-xs text-text-muted hover:text-critical py-1 px-2 flex items-center gap-1 self-start sm:self-auto"
                        >
                          <X size={12} />
                          <span>Clear Selection</span>
                        </button>
                      </div>

                      {/* Cryptographic Hashes */}
                      <div className="p-3 bg-bg-primary border border-border rounded space-y-2 text-2xs font-mono">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-text-muted">
                          <span className="flex items-center gap-1.5 shrink-0">
                            <Hash size={11} className="text-accent-blue" />
                            <span>SHA-256 Digest:</span>
                          </span>
                          <div className="flex items-center gap-2">
                            <span className="text-accent-blue break-all">{selectedFile.sha256}</span>
                            <button
                              type="button"
                              onClick={() => handleCopyHash(selectedFile.sha256)}
                              className="text-text-muted hover:text-text-primary p-0.5"
                              title="Copy SHA-256"
                            >
                              {copiedHash ? <Check size={11} className="text-success" /> : <Copy size={11} />}
                            </button>
                          </div>
                        </div>
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-text-muted pt-1 border-t border-border">
                          <span className="flex items-center gap-1.5 shrink-0">
                            <Clock size={11} />
                            <span>Ingress Timestamp:</span>
                          </span>
                          <span className="text-text-secondary">{formatDate(selectedFile.uploadedAt)}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* MODE 2: RAW RFC 822 STREAM TEXT */}
              {mode === 'RAW_TEXT' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-2xs text-text-muted flex-wrap gap-2">
                    <span>Paste raw RFC 822 / RFC 5322 email headers and message body:</span>
                    <button
                      type="button"
                      onClick={() => setRawText(DEFAULT_SAMPLE_RFC)}
                      className="text-accent-blue hover:underline cursor-pointer"
                    >
                      Paste Default RFC 822 Header
                    </button>
                  </div>
                  <textarea
                    value={rawText}
                    onChange={(e) => setRawText(e.target.value)}
                    rows={12}
                    placeholder="Paste RFC 822 MIME message (Received, From, To, Subject, Content-Type)..."
                    className="input w-full font-mono text-2xs leading-relaxed resize-y bg-bg-primary"
                  />
                  <div className="flex items-center justify-between text-2xs text-text-muted">
                    <span>Byte size: {new TextEncoder().encode(rawText).byteLength} bytes</span>
                    <button
                      type="button"
                      onClick={handleRawTextSubmit}
                      className="btn-secondary text-xs px-3 py-1"
                    >
                      Prepare Buffer for Analysis
                    </button>
                  </div>
                </div>
              )}

              {/* Instant Test Presets */}
              {samples.length > 0 && (
                <div className="p-3 bg-bg-tertiary border border-border rounded space-y-2">
                  <div className="flex items-center gap-1.5 text-2xs font-semibold text-text-primary">
                    <Sparkles size={12} className="text-accent-blue" />
                    <span>Instant Real-Time Test Samples:</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {samples.map((s) => (
                      <button
                        key={s.filename}
                        type="button"
                        onClick={() => loadSample(s)}
                        className="btn-secondary text-2xs py-1 px-2.5 font-mono flex items-center gap-1 hover:border-accent-blue"
                      >
                        <FileCode size={11} />
                        <span>{s.filename}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Error Box */}
              {error && (
                <div className="p-3 rounded bg-critical-muted border border-critical-border text-critical text-xs flex items-center gap-2">
                  <AlertTriangle size={14} className="flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              {/* Triage Trigger Action */}
              <div className="pt-2">
                <button
                  type="button"
                  onClick={runAnalysis}
                  disabled={!selectedFile}
                  className="btn-primary w-full py-2.5 flex items-center justify-center gap-2 text-xs sm:text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Play size={14} className="fill-white" />
                  <span>Execute Real-Time Automated Forensic Triage</span>
                </button>
                <div className="text-center text-2xs text-text-muted mt-2">
                  Triggers RFC 7489 authentication audit, live DNS queries, header hop extraction, and live IOC lookups.
                </div>
              </div>
            </div>
          </div>

          {/* Forensic Ingestion Execution Rules */}
          <div className="panel p-4 bg-bg-secondary space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-primary block">
              Active Triage Engine Capabilities
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-2xs font-mono">
              <div className="p-2 rounded bg-bg-tertiary border border-border flex items-center justify-between">
                <span className="text-text-muted">Hop Trace Analysis:</span>
                <span className="text-success">LIVE (RFC 5322)</span>
              </div>
              <div className="p-2 rounded bg-bg-tertiary border border-border flex items-center justify-between">
                <span className="text-text-muted">Auth Record Audit:</span>
                <span className="text-success">LIVE DNS (SPF/DKIM/DMARC)</span>
              </div>
              <div className="p-2 rounded bg-bg-tertiary border border-border flex items-center justify-between">
                <span className="text-text-muted">Static Doc Inspection:</span>
                <span className="text-success">BYTE PARSER & MACRO DETECTOR</span>
              </div>
              <div className="p-2 rounded bg-bg-tertiary border border-border flex items-center justify-between">
                <span className="text-text-muted">Feed Correlation:</span>
                <span className="text-success">URLHAUS & THREATFOX LIVE</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column (1 Col): Engine Specifications & Recent Scans */}
        <div className="space-y-4">
          {/* Parser Protocol Standards */}
          <div className="panel">
            <div className="panel-header bg-bg-tertiary">
              <span className="text-xs font-semibold uppercase tracking-wider text-text-primary">
                Ingress Compliance Standards
              </span>
            </div>
            <div className="panel-body space-y-3 text-xs">
              <div className="space-y-1">
                <div className="text-2xs text-text-muted uppercase">RFC Protocol Standards</div>
                <div className="p-2 bg-bg-primary border border-border rounded font-mono text-2xs text-text-secondary space-y-1">
                  <div>• RFC 5322: Internet Message Format</div>
                  <div>• RFC 2045-2049: Multi-Part MIME Parsing</div>
                  <div>• RFC 7208: Sender Policy Framework (SPF)</div>
                  <div>• RFC 6376: DomainKeys Identified Mail (DKIM)</div>
                  <div>• RFC 7489: Domain-based Message Authentication (DMARC)</div>
                </div>
              </div>

              <div className="space-y-1 pt-2 border-t border-border">
                <div className="text-2xs text-text-muted uppercase">Security & Data Governance</div>
                <div className="text-2xs text-text-secondary leading-relaxed space-y-1">
                  <p>• <strong className="text-text-primary">Zero Fabrication:</strong> All indicator findings reflect actual byte parsing and live network responses.</p>
                  <p>• <strong className="text-text-primary">Chain-of-Custody:</strong> All inputs receive an immutable FIPS SHA-256 digest at the moment of ingestion.</p>
                  <p>• <strong className="text-text-primary">Attribution Standard:</strong> Originating IP coordinates reflect physical infrastructure nodes, not confirmed threat actor domicile.</p>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Ingress Cases from Database */}
          <div className="panel">
            <div className="panel-header bg-bg-tertiary flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-text-primary">
                Recent Triage Records
              </span>
              <span className="badge bg-bg-secondary border border-border text-text-muted text-2xs font-mono">
                LIVE QUEUE
              </span>
            </div>
            <div className="panel-body p-0 divide-y divide-border">
              {recentCases.length === 0 ? (
                <div className="p-4 text-center text-xs text-text-muted">
                  No cases ingested yet. Analyze an email to begin.
                </div>
              ) : (
                recentCases.map((item) => (
                  <div key={item.id} className="p-3 hover:bg-bg-hover transition-colors flex items-center justify-between">
                    <div className="min-w-0 pr-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-2xs text-accent-blue font-bold">{item.caseId}</span>
                        <span
                          className={`text-2xs font-mono px-1 rounded ${
                            item.riskLevel === 'CRITICAL'
                              ? 'bg-critical-muted text-critical'
                              : item.riskLevel === 'HIGH'
                              ? 'bg-warning-muted text-warning'
                              : 'bg-success-muted text-success'
                          }`}
                        >
                          {item.riskLevel}
                        </span>
                      </div>
                      <div className="text-xs font-medium text-text-primary truncate mt-0.5">{item.subject}</div>
                      <div className="text-2xs font-mono text-text-muted mt-0.5">
                        {item.fileHash.slice(0, 12)}... · {item.fileName}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => navigate(`/investigation/${item.id}`)}
                      className="btn-secondary text-2xs py-1 px-2.5 shrink-0 flex items-center gap-1"
                    >
                      <span>View</span>
                      <ArrowRight size={10} />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
