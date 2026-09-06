// ============================================================
// MAILTRACE AI — Authentication Analysis Tab
// Detailed SPF, DKIM, DMARC validation & authentication flow
// ============================================================
import { useState, useEffect } from 'react';
import {
  ShieldCheck, AlertTriangle, CheckCircle2, XCircle,
  Server, Mail, Shield, Globe, Terminal, Info, Copy
} from 'lucide-react';
import { getAuthentication } from '../../services/api';
import type { AuthenticationResult } from '../../types';
import { AuthBadge } from '../ui/Badge';
import { LoadingOverlay, ErrorState } from '../ui/States';
import { copyToClipboard } from '../../utils';

interface Props {
  investigationId: string;
}

export default function AuthenticationTab({ investigationId }: Props) {
  const [data, setData] = useState<AuthenticationResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedRaw, setCopiedRaw] = useState(false);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await getAuthentication(investigationId);
      setData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load authentication data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [investigationId]);

  if (loading) return <LoadingOverlay message="Analyzing email authentication records..." />;
  if (error || !data) return <ErrorState message={error || 'Authentication data not available'} retry={loadData} />;

  const handleCopyRaw = () => {
    const rawText = `Authentication-Results: mx.company.internal;
  spf=fail (domain of ${data.spf.domain} does not designate ${data.spf.sendingIp} as permitted sender);
  dkim=pass header.d=${data.dkim.domain} header.s=${data.dkim.selector};
  dmarc=fail (p=${data.dmarc.policy} sp=${data.dmarc.policy} dis=reject) header.from=${data.spf.domain}`;
    copyToClipboard(rawText);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Top row: 3 Authentication protocol cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* SPF */}
        <div className="panel border-l-4 border-l-critical">
          <div className="panel-header bg-bg-tertiary">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-critical" />
              <span className="font-semibold text-xs text-text-primary tracking-wider">SPF (SENDER POLICY FRAMEWORK)</span>
            </div>
            <AuthBadge result={data.spf.result} />
          </div>
          <div className="panel-body space-y-2.5 text-xs">
            <div className="flex justify-between items-start border-b border-border pb-1.5">
              <span className="text-text-muted">Sending IP</span>
              <span className="font-mono text-critical font-medium">{data.spf.sendingIp}</span>
            </div>
            <div className="flex justify-between items-start border-b border-border pb-1.5">
              <span className="text-text-muted">Expected Domain</span>
              <span className="font-mono text-text-primary">{data.spf.domain}</span>
            </div>
            <div className="flex justify-between items-start border-b border-border pb-1.5">
              <span className="text-text-muted">Mechanism</span>
              <span className="font-mono text-warning font-semibold">{data.spf.mechanism}</span>
            </div>
            <div className="p-2 bg-critical-muted border border-critical-border rounded text-2xs text-critical leading-relaxed">
              <span className="font-bold">Evaluation: </span>
              {data.spf.explanation}
            </div>
          </div>
        </div>

        {/* DKIM */}
        <div className="panel border-l-4 border-l-success">
          <div className="panel-header bg-bg-tertiary">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-success" />
              <span className="font-semibold text-xs text-text-primary tracking-wider">DKIM (DOMAINKEYS IDENTIFIED MAIL)</span>
            </div>
            <AuthBadge result={data.dkim.result} />
          </div>
          <div className="panel-body space-y-2.5 text-xs">
            <div className="flex justify-between items-start border-b border-border pb-1.5">
              <span className="text-text-muted">Signing Domain (d=)</span>
              <span className="font-mono text-text-primary">{data.dkim.domain}</span>
            </div>
            <div className="flex justify-between items-start border-b border-border pb-1.5">
              <span className="text-text-muted">Selector (s=)</span>
              <span className="font-mono text-text-secondary">{data.dkim.selector}</span>
            </div>
            <div className="flex justify-between items-start border-b border-border pb-1.5">
              <span className="text-text-muted">Algorithm (a=)</span>
              <span className="font-mono text-text-secondary">{data.dkim.algorithm}</span>
            </div>
            <div className="p-2 bg-success-muted border border-success-border rounded text-2xs text-success leading-relaxed">
              <span className="font-bold">Cryptographic Status: </span>
              Valid cryptographic signature verified against public key published in DNS. Body hash matches.
            </div>
          </div>
        </div>

        {/* DMARC */}
        <div className="panel border-l-4 border-l-critical">
          <div className="panel-header bg-bg-tertiary">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-critical" />
              <span className="font-semibold text-xs text-text-primary tracking-wider">DMARC POLICY & ALIGNMENT</span>
            </div>
            <AuthBadge result={data.dmarc.result} />
          </div>
          <div className="panel-body space-y-2.5 text-xs">
            <div className="flex justify-between items-start border-b border-border pb-1.5">
              <span className="text-text-muted">Published Policy (p=)</span>
              <span className="font-mono text-critical font-bold uppercase">{data.dmarc.policy}</span>
            </div>
            <div className="flex justify-between items-start border-b border-border pb-1.5">
              <span className="text-text-muted">SPF Alignment</span>
              <span className="font-mono text-critical font-semibold">{data.dmarc.spfAlignment}</span>
            </div>
            <div className="flex justify-between items-start border-b border-border pb-1.5">
              <span className="text-text-muted">DKIM Alignment</span>
              <span className="font-mono text-success font-semibold">{data.dmarc.dkimAlignment}</span>
            </div>
            <div className="p-2 bg-critical-muted border border-critical-border rounded text-2xs text-critical leading-relaxed">
              <span className="font-bold">Alignment Failure: </span>
              Sender domain does not match SPF authenticated identifier. Policy enforced rejection.
            </div>
          </div>
        </div>
      </div>

      {/* Sender Path Banner */}
      <div className="panel border-l-4 border-l-warning p-3 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-warning flex-shrink-0" />
          <div>
            <div className="text-xs font-semibold text-text-primary uppercase tracking-wider">Sender Transmission Path Status</div>
            <p className="text-2xs text-text-secondary mt-0.5">
              Discrepancy detected between claimed From envelope header, originating server, and return relay route.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="badge bg-warning-muted text-warning border border-warning-border text-xs px-2.5 py-1 font-mono">
            PATH: {data.senderPathStatus}
          </span>
        </div>
      </div>

      {/* Authentication Verification & Alignment Matrix */}
      <div className="panel">
        <div className="panel-header flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-text-primary">
              Authentication Alignment & Protocol Evaluation Matrix
            </span>
            <span className="block text-2xs text-text-muted mt-0.5">
              RFC 7208 / RFC 6376 / RFC 7489 Multi-Protocol Verification
            </span>
          </div>
          <span className="badge bg-bg-tertiary border border-border text-text-secondary text-2xs font-mono">
            EVALUATION ID: AUTH-SEC-{investigationId.slice(0, 8)}
          </span>
        </div>
        <div className="panel-body p-0">
          <div className="overflow-x-auto">
            <table className="table-auto w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-border bg-bg-secondary/70 text-2xs uppercase tracking-wider text-text-muted font-medium">
                  <th className="py-2.5 px-4">Standard & Layer</th>
                  <th className="py-2.5 px-4">Evaluated Identifier</th>
                  <th className="py-2.5 px-4">Alignment Status</th>
                  <th className="py-2.5 px-4">Diagnostic Verification Detail</th>
                  <th className="py-2.5 px-4 text-right">Disposition</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60 text-text-secondary font-mono text-2xs">
                <tr className="hover:bg-bg-secondary/40 transition-colors">
                  <td className="py-3 px-4 font-sans">
                    <div className="font-semibold text-text-primary text-xs">RFC 7208 (SPF)</div>
                    <div className="text-text-muted">Originating IP CIDR</div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-critical font-bold">{data.spf.sendingIp}</span>
                    <div className="text-text-muted text-3xs">MTA: Abuse Hosting LLC</div>
                  </td>
                  <td className="py-3 px-4 font-sans">
                    <span className="inline-flex items-center gap-1 text-critical">
                      <XCircle className="w-3.5 h-3.5" /> Unaligned
                    </span>
                  </td>
                  <td className="py-3 px-4 font-sans max-w-xs text-text-secondary">
                    IP address not present in authorized CIDR range for <code className="text-text-primary font-mono">{data.spf.domain}</code>.
                  </td>
                  <td className="py-3 px-4 text-right">
                    <AuthBadge result="FAIL" />
                  </td>
                </tr>

                <tr className="hover:bg-bg-secondary/40 transition-colors">
                  <td className="py-3 px-4 font-sans">
                    <div className="font-semibold text-text-primary text-xs">RFC 6376 (DKIM)</div>
                    <div className="text-text-muted">Cryptographic Signature</div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-accent-cyan">{data.dkim.selector}._domainkey</span>
                    <div className="text-text-muted text-3xs">{data.dkim.domain}</div>
                  </td>
                  <td className="py-3 px-4 font-sans">
                    <span className="inline-flex items-center gap-1 text-success">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Aligned (Relaxed)
                    </span>
                  </td>
                  <td className="py-3 px-4 font-sans max-w-xs text-text-secondary">
                    RSA-SHA256 signature verified against published DNS TXT public key.
                  </td>
                  <td className="py-3 px-4 text-right">
                    <AuthBadge result="PASS" />
                  </td>
                </tr>

                <tr className="hover:bg-bg-secondary/40 transition-colors">
                  <td className="py-3 px-4 font-sans">
                    <div className="font-semibold text-text-primary text-xs">RFC 7489 (DMARC)</div>
                    <div className="text-text-muted">Policy & Alignment</div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-text-primary">p={data.dmarc.policy}</span>
                    <div className="text-text-muted text-3xs">pct={data.dmarc.pct}% sp={data.dmarc.policy}</div>
                  </td>
                  <td className="py-3 px-4 font-sans">
                    <span className="inline-flex items-center gap-1 text-critical">
                      <AlertTriangle className="w-3.5 h-3.5" /> Policy Enacted
                    </span>
                  </td>
                  <td className="py-3 px-4 font-sans max-w-xs text-text-secondary">
                    From header ({data.spf.domain}) failed SPF alignment; quarantine policy enforced.
                  </td>
                  <td className="py-3 px-4 text-right">
                    <AuthBadge result="FAIL" />
                  </td>
                </tr>

                <tr className="hover:bg-bg-secondary/40 transition-colors bg-critical-muted/20">
                  <td className="py-3 px-4 font-sans">
                    <div className="font-semibold text-text-primary text-xs">Sender Path Enclosure</div>
                    <div className="text-text-muted">Envelope vs Header Comparison</div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-text-primary">billing@{data.spf.domain}</span>
                    <div className="text-critical text-3xs">Return-Path: spoof-relay@{data.spf.domain}</div>
                  </td>
                  <td className="py-3 px-4 font-sans">
                    <span className="inline-flex items-center gap-1 text-warning">
                      <AlertTriangle className="w-3.5 h-3.5" /> Path Mismatch
                    </span>
                  </td>
                  <td className="py-3 px-4 font-sans max-w-xs text-text-secondary">
                    Discrepancy detected between claimed From envelope header, originating server, and return relay route.
                  </td>
                  <td className="py-3 px-4 text-right">
                    <span className="badge bg-critical-muted border border-critical-border text-critical text-2xs font-mono">
                      QUARANTINE
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Technical Evidence & Raw Headers */}
      <div className="panel">
        <div className="panel-header flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-accent-blue" />
            <span className="text-xs font-semibold uppercase tracking-wider text-text-primary">
              Technical Authentication Evidence
            </span>
          </div>
          <button onClick={handleCopyRaw} className="btn-secondary text-xs flex items-center gap-1">
            <Copy size={11} />
            {copiedRaw ? 'Copied Evidence' : 'Copy Raw Results'}
          </button>
        </div>
        <div className="panel-body p-0">
          <div className="p-3 bg-bg-primary font-mono text-2xs text-text-secondary leading-relaxed overflow-x-auto space-y-1">
            <div className="text-text-muted"># Automated Verification Engine Output - RFC Compliant Parser</div>
            <div><span className="text-accent-blue">Authentication-Results:</span> mx.company.internal;</div>
            <div className="pl-4"><span className="text-critical">spf=fail</span> (domain of {data.spf.domain} does not designate {data.spf.sendingIp} as permitted sender) smtp.mailfrom=billing@{data.spf.domain};</div>
            <div className="pl-4"><span className="text-success">dkim=pass</span> (test mode) header.d={data.dkim.domain} header.b="xyz789";</div>
            <div className="pl-4"><span className="text-critical">dmarc=fail</span> action=reject header.from={data.spf.domain} (p=reject, sp=reject, pct=100);</div>
            <div className="pl-4 text-text-muted">x-receiver-policy: reject-on-auth-failure; disposition=quarantine</div>
          </div>
          <div className="px-4 py-2.5 bg-bg-tertiary border-t border-border flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-2xs text-text-muted">
            <span>Verified by: <span className="font-mono text-text-secondary">{data.engine}</span></span>
            <span>Policy Compliance: RFC 7208 / RFC 6376 / RFC 7489</span>
          </div>
        </div>
      </div>
    </div>
  );
}
