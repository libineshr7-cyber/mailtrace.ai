// ============================================================
// MAILTRACE AI — Security Overview Page
// Main SOC dashboard: metrics, investigations table, threat dist, activity
// ============================================================
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderSearch, AlertTriangle, ShieldAlert, GitBranch, RefreshCw
} from 'lucide-react';
import { getInvestigations, getOverviewStats, getTimeline, type OverviewStats } from '../services/api';
import { RiskBadge, AuthBadge, StatusBadge } from '../components/ui/Badge';
import { formatRelative, truncateMiddle } from '../utils';
import type { Investigation, TimelineEvent } from '../types';

interface MetricCardProps {
  icon: React.ReactNode;
  label: string;
  value: number;
  description: string;
  valueClass?: string;
}

function MetricCard({ icon, label, value, description, valueClass = 'text-text-primary' }: MetricCardProps) {
  return (
    <div className="panel p-4 flex flex-col gap-2">
      <div className="flex items-center gap-2">
        {icon}
        <span className="text-xs font-medium text-text-muted uppercase tracking-wide">{label}</span>
      </div>
      <span className={`text-2xl font-bold font-mono leading-none ${valueClass}`}>{value}</span>
      <span className="text-2xs text-text-muted">{description}</span>
    </div>
  );
}

function severityDot(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return 'bg-critical';
    case 'HIGH':     return 'bg-orange-400';
    case 'MEDIUM':   return 'bg-warning';
    case 'LOW':      return 'bg-success';
    default:         return 'bg-text-muted';
  }
}

interface DistRowProps {
  label: string;
  count: number;
  total: number;
  dotClass: string;
}

function DistRow({ label, count, total, dotClass }: DistRowProps) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <div className="flex items-center gap-3 py-1.5">
      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${dotClass}`} />
      <span className="text-xs text-text-secondary w-16 flex-shrink-0">{label}</span>
      <div className="flex-1 h-1 bg-bg-tertiary rounded-full overflow-hidden">
        <div
          className={`h-full ${dotClass} opacity-70 rounded-full transition-all`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs font-mono text-text-primary w-4 text-right flex-shrink-0">{count}</span>
    </div>
  );
}

export default function OverviewPage() {
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [stats, setStats] = useState<OverviewStats>({
    activeInvestigations: 0,
    criticalCases: 0,
    criticalIOCs: 0,
    correlatedCampaigns: 0,
    threatDistribution: { critical: 0, high: 0, medium: 0, low: 0 }
  });
  const [recentEvents, setRecentEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const [invs, ovStats] = await Promise.all([
        getInvestigations(),
        getOverviewStats()
      ]);
      setInvestigations(invs);
      setStats(ovStats);

      if (invs.length > 0) {
        const events = await getTimeline(invs[0].id).catch(() => []);
        setRecentEvents(events.slice(-5).reverse());
      }
    } catch (err) {
      console.error('Failed to load overview data', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const threatTotal =
    stats.threatDistribution.critical +
    stats.threatDistribution.high +
    stats.threatDistribution.medium +
    stats.threatDistribution.low;

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base sm:text-lg font-semibold text-text-primary">Security Overview</h1>
          <p className="text-xs sm:text-sm text-text-muted mt-0.5">
            Email threat investigations and live forensic intelligence
          </p>
        </div>
        <button onClick={loadData} className="btn-secondary text-xs flex items-center gap-1">
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Metric row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5 sm:gap-4">
        <MetricCard
          icon={<FolderSearch size={15} className="text-accent-blue" />}
          label="Active Investigations"
          value={stats.activeInvestigations}
          description="Live cases in database"
          valueClass="text-accent-blue"
        />
        <MetricCard
          icon={<AlertTriangle size={15} className="text-critical" />}
          label="Critical Cases"
          value={stats.criticalCases}
          description="Require immediate review"
          valueClass="text-critical"
        />
        <MetricCard
          icon={<ShieldAlert size={15} className="text-critical" />}
          label="Total Extracted IOCs"
          value={stats.criticalIOCs}
          description="Across ingested envelopes"
          valueClass="text-critical"
        />
        <MetricCard
          icon={<GitBranch size={15} className="text-warning" />}
          label="Correlated Campaigns"
          value={stats.correlatedCampaigns}
          description="Multi-case threat clusters"
          valueClass="text-warning"
        />
      </div>

      {/* Main content grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Recent Investigations */}
        <div className="lg:col-span-2 panel">
          <div className="panel-header">
            <span className="text-sm font-semibold text-text-primary">Recent Investigations</span>
            <span className="text-2xs text-text-muted font-mono">{investigations.length} cases</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left px-4 py-2 text-text-muted font-medium whitespace-nowrap">Case ID</th>
                  <th className="text-left px-4 py-2 text-text-muted font-medium">Subject</th>
                  <th className="text-left px-4 py-2 text-text-muted font-medium whitespace-nowrap">Sender</th>
                  <th className="text-left px-4 py-2 text-text-muted font-medium">Risk</th>
                  <th className="text-left px-4 py-2 text-text-muted font-medium">Auth</th>
                  <th className="text-left px-4 py-2 text-text-muted font-medium">IOCs</th>
                  <th className="text-left px-4 py-2 text-text-muted font-medium whitespace-nowrap">Last Activity</th>
                  <th className="text-left px-4 py-2 text-text-muted font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {investigations.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-4 text-center text-text-muted">
                      No investigations recorded yet. Ingest an email file to start.
                    </td>
                  </tr>
                ) : (
                  investigations.slice(0, 8).map((inv: Investigation) => (
                    <tr
                      key={inv.id}
                      className="border-b border-border table-row-hover"
                      onClick={() => navigate(`/investigation/${inv.id}`)}
                    >
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className="font-mono text-accent-blue hover:underline cursor-pointer">
                          {inv.caseId}
                        </span>
                      </td>
                      <td className="px-4 py-3 max-w-xs">
                        <span className="text-text-primary block truncate" title={inv.subject}>
                          {truncateMiddle(inv.subject, 40)}
                        </span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className="font-mono text-xs text-text-muted">
                          {truncateMiddle(inv.sender, 32)}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <RiskBadge level={inv.riskLevel} />
                      </td>
                      <td className="px-4 py-3">
                        <AuthBadge result={inv.authStatus} />
                      </td>
                      <td className="px-4 py-3 font-mono text-text-primary text-center">
                        {inv.iocCount}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-text-muted">
                        {formatRelative(inv.updatedAt)}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={inv.status} />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Threat Distribution + Recent Activity */}
        <div className="lg:col-span-1 flex flex-col gap-4">
          {/* Threat Distribution */}
          <div className="panel">
            <div className="panel-header">
              <span className="text-sm font-semibold text-text-primary">Threat Distribution</span>
            </div>
            <div className="panel-body py-3">
              <DistRow label="Critical" count={stats.threatDistribution.critical} total={threatTotal} dotClass="bg-critical" />
              <DistRow label="High"     count={stats.threatDistribution.high}     total={threatTotal} dotClass="bg-orange-400" />
              <DistRow label="Medium"   count={stats.threatDistribution.medium}   total={threatTotal} dotClass="bg-warning" />
              <DistRow label="Low"      count={stats.threatDistribution.low}      total={threatTotal} dotClass="bg-success" />
            </div>
          </div>

          {/* Investigation Activity */}
          <div className="panel flex-1">
            <div className="panel-header">
              <span className="text-sm font-semibold text-text-primary">Live Case Activity</span>
            </div>
            <div className="panel-body space-y-0 divide-y divide-border">
              {recentEvents.length === 0 ? (
                <div className="p-3 text-2xs text-text-muted text-center">
                  No recent activity logged.
                </div>
              ) : (
                recentEvents.map((event: TimelineEvent) => (
                  <div key={event.id} className="flex items-start gap-2.5 py-2.5 first:pt-0 last:pb-0">
                    <span className={`mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0 ${severityDot(event.severity)}`} />
                    <div className="flex flex-col gap-0.5 min-w-0">
                      <span className="font-mono text-2xs text-text-muted leading-none">
                        {formatRelative(event.timestamp)}
                      </span>
                      <span className="text-xs text-text-primary leading-snug">
                        {event.event}
                      </span>
                    </div>
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
