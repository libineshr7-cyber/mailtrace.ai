// ============================================================
// MAILTRACE AI — Audit Logs Page
// SOC Security event, triage actions & forensic audit trail
// ============================================================
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ScrollText, Search, Download, Filter, ShieldCheck,
  CheckCircle2, AlertCircle, Clock, Check, RefreshCw
} from 'lucide-react';
import { getAuditLogs } from '../services/api';
import type { AuditLog } from '../types';
import { formatDate } from '../utils';
import { LoadingOverlay } from '../components/ui/States';

export default function AuditLogsPage() {
  const navigate = useNavigate();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState<string>('ALL');
  const [copiedCSV, setCopiedCSV] = useState(false);

  const actions = ['ALL', 'UPLOADED_EMAIL', 'COMPLETED_ANALYSIS', 'OPENED_CASE', 'GENERATED_REPORT', 'UPDATED_STATUS', 'REVOKE_FROM_MAILBOXES', 'BLOCK_SENDER_DOMAIN', 'LOGIN'];

  const loadData = () => {
    setLoading(true);
    getAuditLogs()
      .then((res) => setLogs(res))
      .catch((err) => console.error('Failed to load audit logs', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, []);

  const filtered = logs.filter((log) => {
    const matchesAction = actionFilter === 'ALL' || log.action === actionFilter;
    const matchesSearch =
      !searchQuery ||
      log.user.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (log.caseId && log.caseId.toLowerCase().includes(searchQuery.toLowerCase())) ||
      log.object.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesAction && matchesSearch;
  });

  const handleExportCSV = () => {
    const headers = ['Timestamp', 'User', 'Action', 'CaseId', 'Object', 'Result', 'IPAddress'];
    const rows = filtered.map((l) => [
      l.timestamp,
      l.user,
      l.action,
      l.caseId || '',
      l.object,
      l.result,
      l.ipAddress || '',
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `MailTrace_Audit_Logs_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    setCopiedCSV(true);
    setTimeout(() => setCopiedCSV(false), 2000);
  };

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-base sm:text-lg font-semibold text-text-primary">Audit Logs</h1>
          <p className="text-xs sm:text-sm text-text-muted mt-0.5">
            Immutable forensic audit record tracking analyst actions, engine telemetry, and access events
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={loadData} className="btn-secondary text-xs flex items-center gap-1">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            <span>Sync</span>
          </button>
          <button
            onClick={handleExportCSV}
            className="btn-secondary text-xs flex items-center gap-1.5 self-start sm:self-auto"
          >
            {copiedCSV ? <Check size={12} className="text-success" /> : <Download size={12} />}
            {copiedCSV ? 'CSV Exported' : 'Export Audit CSV'}
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 sm:gap-3">
        {[
          { label: 'Recorded Events', value: logs.length, color: 'text-text-primary' },
          { label: 'Successful Operations', value: logs.filter((l) => l.result === 'SUCCESS').length, color: 'text-success' },
          { label: 'Security Warnings', value: logs.filter((l) => l.result === 'WARNING').length, color: 'text-warning' },
          { label: 'Active Analysts', value: new Set(logs.map(l => l.user)).size, color: 'text-accent-blue' },
        ].map((s) => (
          <div key={s.label} className="panel px-3 sm:px-4 py-2 sm:py-2.5 flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-3">
            <span className={`text-base sm:text-lg font-semibold font-mono ${s.color}`}>{s.value}</span>
            <span className="text-2xs sm:text-xs text-text-muted">{s.label}</span>
          </div>
        ))}
      </div>

      {/* Filter and Search Bar */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap">
          {actions.map((act) => (
            <button
              key={act}
              onClick={() => setActionFilter(act)}
              className={`px-3 py-1.5 text-xs rounded font-medium transition-colors font-mono ${
                actionFilter === act
                  ? 'bg-accent-blue-muted text-accent-blue-light border border-accent-blue'
                  : 'bg-bg-tertiary text-text-secondary border border-border hover:bg-bg-hover hover:text-text-primary'
              }`}
            >
              {act}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-72">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search action, case, user..."
            className="input pl-7 text-xs py-1.5"
          />
        </div>
      </div>

      {/* Audit Logs Table */}
      <div className="panel overflow-hidden">
        {loading && <LoadingOverlay message="Querying audit records..." />}
        <div className="overflow-x-auto">
          <table className="w-full text-xs min-w-[700px]">
          <thead>
            <tr className="border-b border-border bg-bg-tertiary text-text-muted">
              <th className="text-left px-4 py-2.5 font-medium">Timestamp (UTC)</th>
              <th className="text-left px-4 py-2.5 font-medium">Investigator / Actor</th>
              <th className="text-left px-4 py-2.5 font-medium">Action Performed</th>
              <th className="text-left px-4 py-2.5 font-medium">Case Reference</th>
              <th className="text-left px-4 py-2.5 font-medium">Target Object</th>
              <th className="text-left px-4 py-2.5 font-medium">Outcome</th>
              <th className="text-right px-4 py-2.5 font-medium">Client IP</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="p-4 text-center text-text-muted">
                  No audit log records match filter criteria.
                </td>
              </tr>
            ) : (
              filtered.map((log) => (
                <tr key={log.id} className="border-b border-border table-row-hover">
                  <td className="px-4 py-3 font-mono text-text-secondary text-2xs">
                    {formatDate(log.timestamp)}
                  </td>
                  <td className="px-4 py-3 font-medium text-text-primary">
                    {log.user}
                  </td>
                  <td className="px-4 py-3">
                    <span className="badge bg-bg-tertiary border border-border text-text-primary font-mono text-2xs">
                      {log.action}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {log.caseId ? (
                      <button
                        onClick={() => navigate('/investigations')}
                        className="font-mono text-accent-blue hover:underline cursor-pointer"
                      >
                        {log.caseId}
                      </button>
                    ) : (
                      <span className="text-text-muted">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono text-text-secondary max-w-xs truncate">
                    {log.object}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`badge border text-2xs font-mono ${
                        log.result === 'SUCCESS'
                          ? 'bg-success-muted text-success border-success-border'
                          : log.result === 'WARNING'
                          ? 'bg-warning-muted text-warning border-warning-border'
                          : 'bg-critical-muted text-critical border-critical-border'
                      }`}
                    >
                      {log.result}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-2xs text-text-muted">
                    {log.ipAddress || '127.0.0.1 (Local)'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        </div>
        <div className="px-4 py-2.5 bg-bg-tertiary border-t border-border flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-2xs text-text-muted">
          <span>Chain-of-Custody Compliance: RFC 3161 Timestamping Protocol</span>
          <span>Showing {filtered.length} of {logs.length} audit entries</span>
        </div>
      </div>
    </div>
  );
}
