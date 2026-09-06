import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { FolderSearch, MailPlus, ExternalLink, Search, Filter, RefreshCw } from 'lucide-react';
import { getInvestigations } from '../services/api';
import { RiskBadge, StatusBadge } from '../components/ui/Badge';
import { EmptyState, LoadingOverlay } from '../components/ui/States';
import { formatDateShort, truncateMiddle } from '../utils';
import type { Investigation, RiskLevel, CaseStatus } from '../types';

export default function InvestigationsPage() {
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'ALL'>('ALL');
  const [statusFilter, setStatusFilter] = useState<CaseStatus | 'ALL'>('ALL');

  const loadData = () => {
    setLoading(true);
    getInvestigations()
      .then((data) => setInvestigations(data))
      .catch((err) => console.error('Failed to load investigations', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, []);

  const filtered = investigations.filter(inv => {
    const q = search.toLowerCase();
    const matchSearch = !search || inv.caseId.toLowerCase().includes(q) || inv.subject.toLowerCase().includes(q) || inv.sender.toLowerCase().includes(q);
    const matchRisk = riskFilter === 'ALL' || inv.riskLevel === riskFilter;
    const matchStatus = statusFilter === 'ALL' || inv.status === statusFilter;
    return matchSearch && matchRisk && matchStatus;
  });

  const stats = {
    total: investigations.length,
    investigating: investigations.filter(i => i.status === 'INVESTIGATING').length,
    critical: investigations.filter(i => i.riskLevel === 'CRITICAL').length,
    resolved: investigations.filter(i => i.status === 'RESOLVED').length,
  };

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-base sm:text-lg font-semibold text-text-primary">Investigations</h1>
          <p className="text-xs sm:text-sm text-text-muted mt-0.5">Email threat investigation cases</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={loadData} className="btn-secondary text-xs">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            <span>Sync</span>
          </button>
          <button onClick={() => navigate('/email-analysis')} className="btn-primary text-xs w-full sm:w-auto justify-center">
            <MailPlus size={13} />
            New Investigation
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 sm:gap-3">
        {[
          { label: 'Total Cases', value: stats.total, color: 'text-text-primary' },
          { label: 'Investigating', value: stats.investigating, color: 'text-warning' },
          { label: 'Critical Risk', value: stats.critical, color: 'text-critical' },
          { label: 'Resolved', value: stats.resolved, color: 'text-success' },
        ].map(s => (
          <div key={s.label} className="panel px-3.5 py-2.5 flex items-center gap-3">
            <span className={`text-base sm:text-lg font-semibold font-mono ${s.color}`}>{s.value}</span>
            <span className="text-xs text-text-muted">{s.label}</span>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-2.5 sm:gap-3">
        <div className="relative flex-1 max-w-none sm:max-w-xs">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search case ID, subject, sender..." className="input pl-7 text-xs" />
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Filter size={12} className="text-text-muted shrink-0" />
          <select value={riskFilter} onChange={e => setRiskFilter(e.target.value as RiskLevel | 'ALL')} className="select flex-1 sm:w-36 text-xs">
            <option value="ALL">All Risk</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={statusFilter} onChange={e => setStatusFilter(e.target.value as CaseStatus | 'ALL')} className="select flex-1 sm:w-40 text-xs">
            <option value="ALL">All Status</option>
            <option value="NEW">New</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="CONTAINED">Contained</option>
            <option value="RESOLVED">Resolved</option>
            <option value="ARCHIVED">Archived</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="panel overflow-hidden">
        {loading && <LoadingOverlay message="Fetching investigations from database..." />}
        <div className="overflow-x-auto">
          <table className="w-full text-xs min-w-[700px]">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Case ID</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Subject</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Risk</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Created</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Analyst</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">IOCs</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Status</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={8}><EmptyState title="No investigations found" description="Adjust filters or ingest an email to create a new investigation." icon={FolderSearch} /></td></tr>
            ) : filtered.map(inv => (
              <tr key={inv.id} className="border-b border-border table-row-hover" onClick={() => navigate(`/investigation/${inv.id}`)}>
                <td className="px-4 py-3">
                  <span className="font-mono text-accent-blue hover:underline cursor-pointer">{inv.caseId}</span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-text-primary" title={inv.subject}>{truncateMiddle(inv.subject, 44)}</span>
                  <p className="text-2xs text-text-muted font-mono mt-0.5 truncate max-w-[200px]">{inv.sender}</p>
                </td>
                <td className="px-4 py-3"><RiskBadge level={inv.riskLevel} /></td>
                <td className="px-4 py-3 text-text-muted">{formatDateShort(inv.createdAt)}</td>
                <td className="px-4 py-3 text-text-muted">{inv.analyst}</td>
                <td className={`px-4 py-3 font-mono font-semibold ${inv.iocCount > 5 ? 'text-critical' : 'text-text-primary'}`}>{inv.iocCount}</td>
                <td className="px-4 py-3"><StatusBadge status={inv.status} /></td>
                <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                  <button onClick={() => navigate(`/investigation/${inv.id}`)} className="btn-ghost text-xs flex items-center gap-1">
                    <ExternalLink size={11} /> Open
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
        {/* Pagination / Count */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-border">
          <span className="text-xs text-text-muted">Showing {filtered.length} of {investigations.length} investigations</span>
        </div>
      </div>
    </div>
  );
}
