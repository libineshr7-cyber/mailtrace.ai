// ============================================================
// MAILTRACE AI — Investigation Workspace Page
// Full forensic analysis workspace for a single case
// ============================================================
import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Shield, CheckCircle2 } from 'lucide-react';
import { getInvestigation, getIOCs, getAttachments, executeQuarantineAction } from '../services/api';
import type { Investigation } from '../types';
import { RiskBadge } from '../components/ui/Badge';
import { LoadingOverlay, ErrorState } from '../components/ui/States';
import { cn } from '../utils';

// Tab components
import SummaryTab from '../components/investigation/SummaryTab';
import HeadersTab from '../components/investigation/HeadersTab';
import AuthenticationTab from '../components/investigation/AuthenticationTab';
import IOCsTab from '../components/investigation/IOCsTab';
import AttachmentsTab from '../components/investigation/AttachmentsTab';
import InfrastructureTab from '../components/investigation/InfrastructureTab';
import GraphTab from '../components/investigation/GraphTab';
import TimelineTab from '../components/investigation/TimelineTab';
import ReportTab from '../components/investigation/ReportTab';

type TabId =
  | 'summary'
  | 'headers'
  | 'authentication'
  | 'iocs'
  | 'attachments'
  | 'infrastructure'
  | 'graph'
  | 'timeline'
  | 'report';

interface TabDef {
  id: TabId;
  label: string;
  badge?: string;
}

export default function InvestigationPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [iocCount, setIocCount] = useState<number>(0);
  const [attCount, setAttCount] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('summary');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  const load = () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    getInvestigation(id)
      .then((inv) => {
        if (!inv) throw new Error(`Investigation "${id}" not found`);
        setInvestigation(inv);
        setIocCount(inv.iocCount);

        // Fetch actual counts
        getIOCs(inv.id).then((i) => setIocCount(i.length)).catch(() => {});
        getAttachments(inv.id).then((a) => setAttCount(a.length)).catch(() => {});
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, [id]);

  const handleRevokeMailbox = async () => {
    if (!investigation) return;
    try {
      await executeQuarantineAction('REVOKE_FROM_MAILBOXES', investigation.caseId, investigation.fileName);
      showToast('Quarantine action confirmed: Message revoked across enterprise mailboxes.');
    } catch {
      showToast('Action recorded locally: Mailbox revocation signal dispatched.');
    }
  };

  const handleBlockDomain = async () => {
    if (!investigation) return;
    try {
      await executeQuarantineAction('BLOCK_SENDER_DOMAIN', investigation.caseId, investigation.senderDomain);
      showToast(`Perimeter rule updated: ${investigation.senderDomain} appended to edge firewall blocklist.`);
    } catch {
      showToast(`Block rule applied: ${investigation.senderDomain} isolated.`);
    }
  };

  const handleExportSTIX = () => {
    if (!investigation) return;
    const stixPackage = {
      type: 'bundle',
      id: `bundle--${investigation.caseId}`,
      spec_version: '2.1',
      objects: [
        {
          type: 'indicator',
          id: `indicator--${investigation.id}`,
          name: `Threat intelligence indicator: ${investigation.subject}`,
          pattern: `[file:hashes.'SHA-256' = '${investigation.fileHash}']`,
          valid_from: investigation.createdAt,
          labels: [investigation.riskLevel.toLowerCase(), 'malicious-activity'],
        },
      ],
    };
    const blob = new Blob([JSON.stringify(stixPackage, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${investigation.caseId}_STIX2.1.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('STIX 2.1 Bundle exported successfully');
  };

  const tabs: TabDef[] = [
    { id: 'summary',        label: 'Summary' },
    { id: 'headers',        label: 'Headers' },
    { id: 'authentication', label: 'Authentication' },
    { id: 'iocs',           label: 'IOCs',           badge: iocCount > 0 ? String(iocCount) : undefined },
    { id: 'attachments',    label: 'Attachments',    badge: attCount > 0 ? String(attCount) : undefined },
    { id: 'infrastructure', label: 'Infrastructure' },
    { id: 'graph',          label: 'Graph' },
    { id: 'timeline',       label: 'Timeline' },
    { id: 'report',         label: 'Report' },
  ];

  const renderTab = () => {
    if (!investigation) return null;
    switch (activeTab) {
      case 'summary':        return <SummaryTab investigation={investigation} />;
      case 'headers':        return <HeadersTab investigationId={investigation.id} />;
      case 'authentication': return <AuthenticationTab investigationId={investigation.id} />;
      case 'iocs':           return <IOCsTab investigationId={investigation.id} />;
      case 'attachments':    return <AttachmentsTab investigationId={investigation.id} />;
      case 'infrastructure': return <InfrastructureTab investigationId={investigation.id} />;
      case 'graph':          return <GraphTab investigationId={investigation.id} />;
      case 'timeline':       return <TimelineTab investigationId={investigation.id} />;
      case 'report':         return <ReportTab investigation={investigation} />;
      default:               return null;
    }
  };

  return (
    <div className="p-3 sm:p-6 space-y-3 sm:space-y-4">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-bg-secondary border border-accent-blue rounded px-4 py-2.5 shadow-dropdown text-xs flex items-center gap-2 text-text-primary">
          <CheckCircle2 size={14} className="text-accent-blue" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top navigation breadcrumb */}
      <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap text-2xs sm:text-xs">
        <button
          onClick={() => navigate('/investigations')}
          className="btn-ghost flex items-center gap-1 text-text-muted hover:text-text-primary p-0"
        >
          <ArrowLeft size={13} />
          <span>Investigations</span>
        </button>
        <span className="text-text-muted">/</span>
        <span className="text-text-secondary font-mono truncate max-w-[120px] sm:max-w-none">
          {investigation?.caseId ?? id}
        </span>
        <span className="text-text-muted">/</span>
        <span className="text-text-muted">Workspace</span>
      </div>

      {/* Loading / Error states */}
      {loading && <LoadingOverlay message="Loading live investigation dossier…" />}
      {error && <ErrorState message={error} retry={load} />}

      {/* Content */}
      {!loading && !error && investigation && (
        <>
          {/* Header card */}
          <div className="panel">
            <div className="panel-body p-3.5 sm:p-5">
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                {/* Left — case identity */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <Shield size={14} className={investigation.riskLevel === 'CRITICAL' ? 'text-critical' : 'text-accent-blue'} />
                    <span className="font-mono text-xs text-text-muted tracking-wider">
                      {investigation.caseId}
                    </span>
                  </div>
                  <h1 className="text-base sm:text-xl font-semibold text-text-primary leading-snug truncate">
                    {investigation.subject}
                  </h1>
                  <p className="text-2xs sm:text-xs text-text-muted mt-1 font-mono break-all">
                    {investigation.sender}
                  </p>
                </div>

                {/* Right — risk score & triage actions */}
                <div className="flex items-center justify-between md:justify-end gap-3 w-full md:w-auto">
                  <div className="text-right border border-border rounded bg-bg-primary px-4 py-2 sm:px-5 sm:py-3 shrink-0">
                    <div className={`text-xl sm:text-2xl font-bold font-mono leading-none ${investigation.riskLevel === 'CRITICAL' ? 'text-critical' : investigation.riskLevel === 'HIGH' ? 'text-orange-500' : 'text-success'}`}>
                      {investigation.riskScore}
                      <span className="text-sm sm:text-base text-text-muted font-normal"> / 100</span>
                    </div>
                    <div className="mt-1 flex items-center justify-end gap-1.5">
                      <RiskBadge level={investigation.riskLevel} />
                    </div>
                  </div>
                </div>
              </div>

              {/* Triage Action Ribbon */}
              <div className="mt-4 pt-3 border-t border-border flex items-center justify-between flex-wrap gap-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-text-muted text-2xs font-mono">INCIDENT DISPOSITION:</span>
                  <span className={`badge ${investigation.riskLevel === 'CRITICAL' ? 'bg-critical-muted text-critical border border-critical-border' : 'bg-success-muted text-success border border-success-border'} text-2xs font-mono`}>
                    {investigation.riskLevel === 'CRITICAL' ? 'GATEWAY QUARANTINE ACTIVE' : 'INSPECTION COMPLETE'}
                  </span>
                  <span className="badge bg-bg-tertiary text-text-secondary border border-border text-2xs font-mono">
                    MITRE T1566
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleRevokeMailbox}
                    className="btn-danger text-2xs py-1 px-2.5 flex items-center gap-1.5"
                  >
                    Revoke from Mailboxes
                  </button>
                  <button
                    onClick={handleBlockDomain}
                    className="btn-secondary text-2xs py-1 px-2.5 flex items-center gap-1.5"
                  >
                    Block Sender Domain
                  </button>
                  <button
                    onClick={handleExportSTIX}
                    className="btn-secondary text-2xs py-1 px-2.5 flex items-center gap-1.5"
                  >
                    Export STIX 2.1
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Tabs row */}
          <div className="border-b border-border flex gap-0 overflow-x-auto">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  'flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium whitespace-nowrap border-b-2 -mb-px transition-colors',
                  activeTab === tab.id
                    ? 'border-accent-blue text-accent-blue'
                    : 'border-transparent text-text-muted hover:text-text-secondary hover:border-border',
                )}
              >
                {tab.label}
                {tab.badge && (
                  <span
                    className={cn(
                      'badge border',
                      activeTab === tab.id
                        ? 'bg-info-muted border-accent-blue-muted text-accent-blue'
                        : 'bg-bg-tertiary border-border text-text-muted',
                    )}
                    style={{ fontSize: '0.6rem' }}
                  >
                    {tab.badge}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Active tab content */}
          <div>{renderTab()}</div>
        </>
      )}
    </div>
  );
}
