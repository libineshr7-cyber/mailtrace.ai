// ============================================================
// MAILTRACE AI — Evidence Timeline Tab
// Chronological forensic telemetry and audit trail
// ============================================================
import { useState, useEffect } from 'react';
import {
  Clock, Shield, Filter, Search, CheckCircle2,
  AlertTriangle, Server, Network, User, Cpu
} from 'lucide-react';
import { getTimeline } from '../../services/api';
import type { TimelineEvent, TimelineCategory } from '../../types';
import { RiskBadge, Badge } from '../ui/Badge';
import { LoadingOverlay, ErrorState, EmptyState } from '../ui/States';
import { formatTime, formatDate } from '../../utils';

interface Props {
  investigationId: string;
}

const CATEGORY_MAP: Record<TimelineCategory | 'ALL', { label: string; icon: any }> = {
  ALL:            { label: 'All Categories',      icon: Filter },
  AUTHENTICATION: { label: 'Authentication',      icon: Shield },
  IOC:            { label: 'IOC Intelligence',    icon: AlertTriangle },
  NETWORK:        { label: 'Network & Infra',     icon: Network },
  THREAT_INTEL:   { label: 'Threat Intel',        icon: Server },
  ANALYST:        { label: 'Analyst Actions',     icon: User },
  SYSTEM:         { label: 'System Pipeline',     icon: Cpu },
};

export default function TimelineTab({ investigationId }: Props) {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeCategory, setActiveCategory] = useState<TimelineCategory | 'ALL'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const loadTimeline = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await getTimeline(investigationId);
      setEvents(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load timeline');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTimeline();
  }, [investigationId]);

  if (loading) return <LoadingOverlay message="Reconstructing evidence timeline..." />;
  if (error) return <ErrorState message={error} retry={loadTimeline} />;

  const filtered = events.filter((ev) => {
    const matchesCategory = activeCategory === 'ALL' || ev.category === activeCategory;
    const matchesSearch =
      !searchQuery ||
      ev.event.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.evidence.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.source.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const getDotColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'bg-critical border-critical';
      case 'HIGH':     return 'bg-orange-500 border-orange-500';
      case 'MEDIUM':   return 'bg-warning border-warning';
      case 'LOW':      return 'bg-success border-success';
      default:         return 'bg-accent-blue border-accent-blue';
    }
  };

  return (
    <div className="space-y-4">
      {/* Category filter pills & search */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap">
          {(Object.keys(CATEGORY_MAP) as (TimelineCategory | 'ALL')[]).map((cat) => {
            const def = CATEGORY_MAP[cat];
            const count = cat === 'ALL' ? events.length : events.filter((e) => e.category === cat).length;
            return (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`px-2.5 py-1 text-xs rounded font-medium transition-colors flex items-center gap-1.5 ${
                  activeCategory === cat
                    ? 'bg-accent-blue-muted text-accent-blue-light border border-accent-blue'
                    : 'bg-bg-tertiary text-text-secondary border border-border hover:bg-bg-hover hover:text-text-primary'
                }`}
              >
                <span>{def.label}</span>
                <span className="text-2xs font-mono text-text-muted">({count})</span>
              </button>
            );
          })}
        </div>

        <div className="relative w-full sm:w-64">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search timeline evidence..."
            className="input pl-7 text-xs py-1"
          />
        </div>
      </div>

      {/* Timeline Stream */}
      <div className="panel p-3 sm:p-5">
        {filtered.length === 0 ? (
          <EmptyState
            title="No timeline events found"
            description="No events match your current category or search query."
          />
        ) : (
          <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-border">
            {filtered.map((ev) => (
              <div key={ev.id} className="relative group">
                {/* Node dot */}
                <div
                  className={`absolute -left-[23px] top-1.5 w-3 h-3 rounded-full border-2 border-bg-primary shadow-sm ${getDotColor(
                    ev.severity
                  )}`}
                />

                <div className="panel p-3.5 bg-bg-secondary hover:bg-bg-hover transition-colors border border-border">
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-xs font-semibold text-accent-blue">
                          {formatTime(ev.timestamp)}
                        </span>
                        <span className="text-2xs font-mono text-text-muted">
                          {formatDate(ev.timestamp)}
                        </span>
                        <span className="badge bg-bg-tertiary border border-border text-text-secondary text-2xs font-mono">
                          {ev.category}
                        </span>
                      </div>

                      <div className="text-sm font-semibold text-text-primary">
                        {ev.event}
                      </div>

                      <div className="p-2 bg-bg-primary border border-border rounded text-xs text-text-secondary font-mono mt-2 leading-relaxed">
                        {ev.evidence}
                      </div>

                      <div className="flex items-center gap-2 text-2xs text-text-muted mt-2">
                        <span>Attributed Source:</span>
                        <span className="font-mono text-text-secondary font-medium">{ev.source}</span>
                      </div>
                    </div>

                    <div className="flex-shrink-0">
                      {ev.severity !== 'NONE' && <RiskBadge level={ev.severity} />}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="mt-4 pt-3 border-t border-border flex items-center justify-between text-2xs text-text-muted">
          <span>Total Evidence Events: <span className="font-mono text-text-primary">{filtered.length}</span></span>
          <span>Ordering: Strict Chronological Execution Trace</span>
        </div>
      </div>
    </div>
  );
}
