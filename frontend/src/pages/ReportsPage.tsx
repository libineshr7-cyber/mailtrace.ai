// ============================================================
// MAILTRACE AI — Reports Management Page
// Archived and generated DFIR forensic investigation reports
// ============================================================
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText, Download, Eye, Printer, Shield,
  Search, CheckCircle2, Calendar, FilePlus2, RefreshCw
} from 'lucide-react';
import { getInvestigations, getInvestigation } from '../services/api';
import type { Investigation } from '../types';
import { RiskBadge, StatusBadge } from '../components/ui/Badge';
import { formatDateShort, copyToClipboard } from '../utils';
import { LoadingOverlay } from '../components/ui/States';

export default function ReportsPage() {
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 2500);
  };

  const loadData = () => {
    setLoading(true);
    getInvestigations()
      .then((res) => setInvestigations(res))
      .catch((err) => console.error('Failed to load reports', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleExportJSON = async (invId: string, caseId: string) => {
    try {
      const inv = await getInvestigation(invId);
      const reportData = {
        caseId,
        reportType: 'MAILTRACE AI Forensic Evidence Export',
        generatedAt: new Date().toISOString(),
        investigator: inv.analyst || 'Security Analyst',
        investigation: inv,
        compliance: 'ISO/IEC 27037 Digital Evidence Standard',
      };
      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${caseId}_Forensic_Evidence.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast(`JSON export for ${caseId} downloaded`);
    } catch {
      showToast(`Failed to export dossier for ${caseId}`);
    }
  };

  const filtered = investigations.filter((inv) =>
    inv.caseId.toLowerCase().includes(searchQuery.toLowerCase()) ||
    inv.subject.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      {/* Toast */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-bg-secondary border border-accent-blue rounded px-4 py-2.5 shadow-dropdown text-xs flex items-center gap-2 text-text-primary">
          <CheckCircle2 size={14} className="text-accent-blue" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-base sm:text-lg font-semibold text-text-primary">Forensic Reports</h1>
          <p className="text-xs sm:text-sm text-text-muted mt-0.5">
            Cryptographically sealed forensic reports and evidence dossiers
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={loadData} className="btn-secondary text-xs flex items-center gap-1">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            <span>Sync</span>
          </button>
          <button onClick={() => navigate('/email-analysis')} className="btn-primary text-xs self-start sm:self-auto">
            <FilePlus2 size={13} />
            Generate New Report
          </button>
        </div>
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative w-full sm:w-72">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search report by Case ID, subject..."
            className="input pl-7 text-xs py-1.5"
          />
        </div>
        <div className="text-xs text-text-muted font-mono">
          Showing {filtered.length} generated reports
        </div>
      </div>

      {/* Reports Table */}
      <div className="panel overflow-hidden">
        {loading && <LoadingOverlay message="Querying case dossiers..." />}
        <div className="overflow-x-auto">
          <table className="w-full text-xs min-w-[650px]">
          <thead>
            <tr className="border-b border-border bg-bg-tertiary text-text-muted">
              <th className="text-left px-4 py-2.5 font-medium">Case ID</th>
              <th className="text-left px-4 py-2.5 font-medium">Subject / Title</th>
              <th className="text-left px-4 py-2.5 font-medium">Threat Level</th>
              <th className="text-left px-4 py-2.5 font-medium">Status</th>
              <th className="text-left px-4 py-2.5 font-medium">Investigator</th>
              <th className="text-left px-4 py-2.5 font-medium">Created Date</th>
              <th className="text-right px-4 py-2.5 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="p-4 text-center text-text-muted">
                  No forensic reports found. Ingest an email to generate a dossier.
                </td>
              </tr>
            ) : (
              filtered.map((inv) => (
                <tr key={inv.id} className="border-b border-border table-row-hover">
                  <td className="px-4 py-3 font-mono text-accent-blue font-medium">
                    {inv.caseId}
                  </td>
                  <td className="px-4 py-3 text-text-primary font-medium max-w-sm truncate">
                    {inv.subject}
                  </td>
                  <td className="px-4 py-3">
                    <RiskBadge level={inv.riskLevel} />
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={inv.status} />
                  </td>
                  <td className="px-4 py-3 text-text-secondary">
                    {inv.analyst}
                  </td>
                  <td className="px-4 py-3 font-mono text-text-muted text-2xs">
                    {formatDateShort(inv.createdAt)}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        onClick={() => navigate(`/investigation/${inv.id}`)}
                        className="btn-ghost text-xs py-1 px-2 flex items-center gap-1"
                        title="Inspect Report"
                      >
                        <Eye size={12} />
                        View Dossier
                      </button>
                      <button
                        onClick={() => handleExportJSON(inv.id, inv.caseId)}
                        className="btn-secondary text-xs py-1 px-2 flex items-center gap-1"
                        title="Download JSON Export"
                      >
                        <Download size={12} />
                        JSON
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        </div>
        <div className="px-4 py-2.5 bg-bg-tertiary border-t border-border flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-2xs text-text-muted">
          <span>Standards: ISO/IEC 27037 Digital Evidence Acquisition · Chain of Custody</span>
          <span>Engine: Digital Evidence Packager v2.4</span>
        </div>
      </div>
    </div>
  );
}
