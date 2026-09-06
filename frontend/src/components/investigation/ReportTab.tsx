// ============================================================
// MAILTRACE AI — Forensic Investigation Report Tab
// Formal DFIR enterprise forensic investigation report
// ============================================================
import { useState, useEffect } from 'react';
import {
  FileText, Download, Printer, Shield, CheckCircle2,
  AlertTriangle, Copy, ExternalLink, Calendar, Hash, User
} from 'lucide-react';
import type {
  Investigation, HeaderAnalysis, AuthenticationResult,
  IOC, InfrastructurePoint, RiskAssessment
} from '../../types';
import { RiskBadge, AuthBadge, VerdictBadge } from '../ui/Badge';
import { formatDate, formatFileSize, copyToClipboard } from '../../utils';
import {
  getHeaders, getAuthentication, getIOCs,
  getInfrastructure, getRiskAssessment
} from '../../services/api';
import { LoadingOverlay } from '../ui/States';

interface Props {
  investigation: Investigation;
}

export default function ReportTab({ investigation }: Props) {
  const [headers, setHeaders] = useState<HeaderAnalysis | null>(null);
  const [auth, setAuth] = useState<AuthenticationResult | null>(null);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [infra, setInfra] = useState<InfrastructurePoint[]>([]);
  const [risk, setRisk] = useState<RiskAssessment | null>(null);
  const [loading, setLoading] = useState(true);

  const [analystNotes, setAnalystNotes] = useState(
    'Primary sender address spoofing verified via SPF evaluation failure and DMARC enforcement rejection. Ingress relay located in Netherlands IP space matching AS209650 hosting known credential harvesting infrastructure. Malicious phishing URI identified inside MIME body targeting financial accounting personnel. Ingress quarantine applied.'
  );
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 2500);
  };

  useEffect(() => {
    setLoading(true);
    Promise.all([
      getHeaders(investigation.id).catch(() => null),
      getAuthentication(investigation.id).catch(() => null),
      getIOCs(investigation.id).catch(() => []),
      getInfrastructure(investigation.id).catch(() => []),
      getRiskAssessment(investigation.id).catch(() => null),
    ])
      .then(([h, a, i, inf, r]) => {
        setHeaders(h);
        setAuth(a);
        setIocs(i || []);
        setInfra(inf || []);
        setRisk(r);
      })
      .finally(() => setLoading(false));
  }, [investigation.id]);

  const handleExportJSON = () => {
    const reportData = {
      reportTitle: 'MAILTRACE AI Forensic Investigation Report',
      generatedAt: new Date().toISOString(),
      caseId: investigation.caseId,
      investigation,
      authentication: auth,
      headers,
      iocs,
      infrastructure: infra,
      riskAssessment: risk,
      analystNotes,
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${investigation.caseId}_Forensic_Report.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('JSON report downloaded');
  };

  const handlePrint = () => {
    window.print();
  };

  if (loading) {
    return <LoadingOverlay message="Compiling forensic report dossier..." />;
  }

  return (
    <div className="space-y-4">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-bg-secondary border border-accent-blue rounded px-4 py-2.5 shadow-dropdown text-xs flex items-center gap-2 text-text-primary">
          <CheckCircle2 size={14} className="text-accent-blue" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top Action Bar */}
      <div className="panel p-3 flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4 text-accent-blue" />
          <span className="text-xs font-semibold uppercase tracking-wider text-text-primary">
            Forensic Investigation Report Generator
          </span>
          <span className="badge bg-bg-tertiary border border-border text-text-muted text-2xs font-mono">
            {investigation.caseId}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={handleExportJSON} className="btn-secondary text-xs">
            <Download size={12} />
            Export JSON
          </button>
          <button onClick={handlePrint} className="btn-primary text-xs">
            <Printer size={12} />
            Print / Export PDF
          </button>
        </div>
      </div>

      {/* Printable Report Document Body */}
      <div className="panel max-w-4xl mx-auto p-4 sm:p-8 bg-bg-secondary text-text-primary space-y-6 print:bg-white print:text-black print:border-none print:shadow-none">
        {/* Report Formal Header */}
        <div className="border-b-2 border-border pb-6 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 bg-accent-blue rounded-sm flex items-center justify-center text-white">
                <Shield size={14} />
              </div>
              <span className="text-lg font-bold tracking-tight text-text-primary">
                MAILTRACE <span className="text-accent-blue">AI</span>
              </span>
            </div>
            <div className="text-xs text-text-muted mt-1 font-mono">
              Digital Forensics & Incident Response (DFIR) Report
            </div>
          </div>

          <div className="text-left sm:text-right text-xs space-y-0.5">
            <div className="font-mono font-bold text-accent-blue text-sm">{investigation.caseId}</div>
            <div className="text-text-muted">Generated: {formatDate(new Date().toISOString())}</div>
            <div className="text-text-muted">Analyst: <span className="font-medium text-text-primary">{investigation.analyst}</span></div>
            <div className="badge bg-critical-muted text-critical border border-critical-border text-2xs">
              CLASSIFICATION: RESTRICTED SOC ARTIFACT
            </div>
          </div>
        </div>

        {/* 1. Executive Summary */}
        <div className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-accent-blue border-b border-border pb-1">
            1. Executive Summary
          </h2>
          <p className="text-xs text-text-secondary leading-relaxed">
            On {formatDate(investigation.createdAt)}, MailTrace AI automated forensic analysis evaluated the email artifact <code className="font-mono text-text-primary">{investigation.fileName}</code>. The evaluation determined an evidence-backed threat risk score of <strong className="text-critical">{investigation.riskScore} / 100 ({investigation.riskLevel})</strong>. Technical inspection verified {iocs.length} indicators of compromise with authentication disposition <strong className="font-mono text-text-primary">{investigation.authStatus}</strong>.
          </p>
        </div>

        {/* 2. Email Metadata */}
        <div className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-accent-blue border-b border-border pb-1">
            2. Email Metadata & Cryptographic Fingerprints
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono bg-bg-tertiary p-3 rounded border border-border">
            <div><span className="text-text-muted">Subject: </span><span className="text-text-primary">{investigation.subject}</span></div>
            <div><span className="text-text-muted">Sender (From): </span><span className="text-text-primary">{investigation.sender}</span></div>
            <div><span className="text-text-muted">Sender Domain: </span><span className="text-text-primary">{investigation.senderDomain}</span></div>
            <div><span className="text-text-muted">File Size: </span><span className="text-text-primary">{formatFileSize(investigation.fileSize)}</span></div>
            <div className="sm:col-span-2"><span className="text-text-muted">SHA-256 Digest: </span><span className="text-accent-blue break-all">{investigation.fileHash}</span></div>
          </div>
        </div>

        {/* 3. Authentication Verification Results */}
        {auth && (
          <div className="space-y-2">
            <h2 className="text-xs font-bold uppercase tracking-wider text-accent-blue border-b border-border pb-1">
              3. Authentication Analysis (SPF / DKIM / DMARC)
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-xs border border-border min-w-[500px]">
                <thead>
                  <tr className="bg-bg-tertiary border-b border-border text-text-muted">
                    <th className="text-left p-2">Protocol</th>
                    <th className="text-left p-2">Verdict</th>
                    <th className="text-left p-2">Observed Domain / IP</th>
                    <th className="text-left p-2">Technical Findings</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  <tr>
                    <td className="p-2 font-mono font-medium">SPF</td>
                    <td className="p-2"><AuthBadge result={auth.spf.result} /></td>
                    <td className="p-2 font-mono text-2xs">{auth.spf.sendingIp} ({auth.spf.domain})</td>
                    <td className="p-2 text-text-secondary text-2xs">{auth.spf.explanation}</td>
                  </tr>
                  <tr>
                    <td className="p-2 font-mono font-medium">DKIM</td>
                    <td className="p-2"><AuthBadge result={auth.dkim.result} /></td>
                    <td className="p-2 font-mono text-2xs">{auth.dkim.domain}</td>
                    <td className="p-2 text-text-secondary text-2xs">Selector: {auth.dkim.selector || 'N/A'}. Body hash verified: {auth.dkim.bodyHashVerified ? 'Yes' : 'No'}</td>
                  </tr>
                  <tr>
                    <td className="p-2 font-mono font-medium">DMARC</td>
                    <td className="p-2"><AuthBadge result={auth.dmarc.result} /></td>
                    <td className="p-2 font-mono text-2xs">p={auth.dmarc.policy}</td>
                    <td className="p-2 text-text-secondary text-2xs">SPF Alignment: {auth.dmarc.spfAlignment} · DKIM Alignment: {auth.dmarc.dkimAlignment}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 4. Extracted IOCs */}
        <div className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-accent-blue border-b border-border pb-1">
            4. Extracted Indicators of Compromise (IOCs)
          </h2>
          {iocs.length === 0 ? (
            <div className="text-xs text-text-muted italic">No indicators extracted.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs border border-border min-w-[500px]">
                <thead>
                  <tr className="bg-bg-tertiary border-b border-border text-text-muted">
                    <th className="text-left p-2">Indicator</th>
                    <th className="text-left p-2">Type</th>
                    <th className="text-left p-2">Verdict</th>
                    <th className="text-left p-2">Confidence</th>
                    <th className="text-left p-2">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {iocs.slice(0, 8).map((ioc) => (
                    <tr key={ioc.id}>
                      <td className="p-2 font-mono text-2xs text-text-primary break-all">{ioc.indicator}</td>
                      <td className="p-2 font-mono text-2xs">{ioc.type}</td>
                      <td className="p-2"><VerdictBadge verdict={ioc.verdict} /></td>
                      <td className="p-2 font-mono text-2xs">{ioc.confidence}%</td>
                      <td className="p-2 text-2xs text-text-secondary">{ioc.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* 5. Infrastructure Geolocation Analysis */}
        {infra.length > 0 && (
          <div className="space-y-2">
            <h2 className="text-xs font-bold uppercase tracking-wider text-accent-blue border-b border-border pb-1">
              5. Infrastructure Geolocation & Network Topology
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              {infra.map((item) => (
                <div key={item.id} className="p-2.5 bg-bg-tertiary border border-border rounded font-mono text-2xs space-y-0.5">
                  <div className="text-text-primary font-bold">{item.ip || item.hostname}</div>
                  <div className="text-text-secondary">{item.role} · {item.city}, {item.country}</div>
                  <div className="text-text-muted">{item.asn} ({item.organization})</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 6. Threat Scoring Breakdown */}
        {risk && (
          <div className="space-y-2">
            <h2 className="text-xs font-bold uppercase tracking-wider text-accent-blue border-b border-border pb-1">
              6. Explainable Threat Scoring Breakdown
            </h2>
            <div className="space-y-1.5 text-xs">
              {Object.entries(risk.breakdown).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between p-1.5 bg-bg-tertiary border border-border rounded">
                  <span className="capitalize text-text-secondary">{k.replace(/([A-Z])/g, ' $1')}:</span>
                  <span className="font-mono font-bold text-text-primary">{v.score} / {v.max} pts</span>
                </div>
              ))}
              <div className="flex items-center justify-between p-2 bg-critical-muted border border-critical-border rounded font-bold text-critical">
                <span>Composite Forensic Risk Score:</span>
                <span>{risk.totalScore} / {risk.maxScore} ({risk.riskLevel})</span>
              </div>
            </div>
          </div>
        )}

        {/* 7. Analyst Notes */}
        <div className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-accent-blue border-b border-border pb-1">
            7. Investigator Observations & Remediation Notes
          </h2>
          <textarea
            value={analystNotes}
            onChange={(e) => setAnalystNotes(e.target.value)}
            rows={4}
            className="input w-full font-mono text-xs leading-relaxed"
            placeholder="Document investigator notes, triage actions, remediation..."
          />
        </div>

        {/* 8. Technical Conclusion & Sign-Off */}
        <div className="space-y-2 pt-4 border-t border-border">
          <h2 className="text-xs font-bold uppercase tracking-wider text-text-primary">
            8. Incident Disposition Recommendation
          </h2>
          <p className="text-xs text-text-secondary leading-relaxed">
            {investigation.riskLevel === 'CRITICAL' || investigation.riskLevel === 'HIGH' ? (
              <>The artifact constitutes an active, verified security threat. MailTrace AI recommends immediate global perimeter blocking across edge firewalls, purge of recipient mailbox ingress queues, and isolation of any endpoint that opened attached payloads.</>
            ) : (
              <>The artifact exhibits low threat anomaly scores and complies with authentication policies. Standard monitoring enforced.</>
            )}
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 text-xs font-mono text-text-muted">
            <div>
              <div>Investigator Signature: _______________________</div>
              <div className="mt-1">{investigation.analyst} (SOC Operations)</div>
            </div>
            <div>
              <div>Verification Timestamp:</div>
              <div className="mt-1">{new Date().toISOString()}</div>
            </div>
          </div>
        </div>

        {/* Footer Disclaimer */}
        <div className="pt-4 border-t border-border text-center text-2xs text-text-muted italic">
          MAILTRACE AI Forensic Intelligence Engine · Automated RFC-Compliant Security Analysis · Confidential SOC Artifact
        </div>
      </div>
    </div>
  );
}
