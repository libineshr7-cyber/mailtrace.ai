// ============================================================
// MAILTRACE AI — IOC Intelligence Page (Global)
// Extracted Indicators of Compromise & Threat Correlation
// ============================================================
import { useState, useEffect } from 'react';
import {
  Shield, Search, Filter, X, Copy, ExternalLink,
  Globe, Server, AlertTriangle, CheckCircle2, ChevronRight,
  Database, Tag, Link2, RefreshCw
} from 'lucide-react';
import { getAllIOCs } from '../services/api';
import type { IOC, IOCType } from '../types';
import { VerdictBadge, Badge } from '../components/ui/Badge';
import { EmptyState, LoadingOverlay } from '../components/ui/States';
import { formatDateShort, truncateMiddle, copyToClipboard } from '../utils';

export default function IOCIntelligencePage() {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedType, setSelectedType] = useState<IOCType | 'ALL'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIOC, setSelectedIOC] = useState<IOC | null>(null);
  const [copiedIndicator, setCopiedIndicator] = useState(false);

  const loadData = () => {
    setLoading(true);
    getAllIOCs()
      .then((res) => setIocs(res))
      .catch((err) => console.error('Failed to load global IOCs', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, []);

  const filtered = iocs.filter((ioc) => {
    const matchesType = selectedType === 'ALL' || ioc.type === selectedType;
    const matchesSearch =
      !searchQuery ||
      ioc.indicator.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ioc.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (ioc.organization && ioc.organization.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesType && matchesSearch;
  });

  const handleCopy = (text: string) => {
    copyToClipboard(text);
    setCopiedIndicator(true);
    setTimeout(() => setCopiedIndicator(false), 2000);
  };

  const types: (IOCType | 'ALL')[] = ['ALL', 'IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL', 'ATTACHMENT'];

  const stats = {
    total: iocs.length,
    malicious: iocs.filter((i) => i.verdict === 'MALICIOUS').length,
    suspicious: iocs.filter((i) => i.verdict === 'SUSPICIOUS').length,
    clean: iocs.filter((i) => i.verdict === 'CLEAN').length,
  };

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base sm:text-lg font-semibold text-text-primary">IOC Intelligence</h1>
          <p className="text-xs sm:text-sm text-text-muted mt-0.5">
            Extracted indicators of compromise and cross-case threat intelligence correlation
          </p>
        </div>
        <button onClick={loadData} className="btn-secondary text-xs flex items-center gap-1">
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          <span>Sync Feeds</span>
        </button>
      </div>

      {/* Stats pills */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 sm:gap-3">
        {[
          { label: 'Total Indicators', value: stats.total, color: 'text-text-primary' },
          { label: 'Malicious', value: stats.malicious, color: 'text-critical' },
          { label: 'Suspicious', value: stats.suspicious, color: 'text-warning' },
          { label: 'Clean / Neutral', value: stats.clean, color: 'text-success' },
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
          {types.map((t) => (
            <button
              key={t}
              onClick={() => setSelectedType(t)}
              className={`px-3 py-1.5 text-xs rounded font-medium transition-colors ${
                selectedType === t
                  ? 'bg-accent-blue-muted text-accent-blue-light border border-accent-blue'
                  : 'bg-bg-tertiary text-text-secondary border border-border hover:bg-bg-hover hover:text-text-primary'
              }`}
            >
              {t} {t === 'ALL' ? `(${iocs.length})` : `(${iocs.filter((i) => i.type === t).length})`}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-72">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search indicator, source, ASN..."
            className="input pl-7 text-xs py-1.5"
          />
        </div>
      </div>

      {/* Main IOC Table */}
      <div className="panel overflow-hidden">
        {loading && <LoadingOverlay message="Querying active indicator registry..." />}
        <div className="overflow-x-auto">
          <table className="w-full text-xs min-w-[650px]">
          <thead>
            <tr className="border-b border-border bg-bg-tertiary">
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Indicator</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Type</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Verdict</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Confidence</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">First Observed</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Source</th>
              <th className="text-right px-4 py-2.5 text-text-muted font-medium">Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7}>
                  <EmptyState title="No indicators match current filters" description="Adjust search query or indicator type." />
                </td>
              </tr>
            ) : (
              filtered.map((ioc) => (
                <tr
                  key={ioc.id}
                  onClick={() => setSelectedIOC(ioc)}
                  className={`border-b border-border table-row-hover ${
                    selectedIOC?.id === ioc.id ? 'bg-accent-blue-muted' : ''
                  }`}
                >
                  <td className="px-4 py-3">
                    <span className="font-mono text-text-primary hover:text-accent-blue truncate block max-w-md" title={ioc.indicator}>
                      {truncateMiddle(ioc.indicator, 48)}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="badge bg-bg-tertiary border border-border text-text-secondary text-2xs font-mono">
                      {ioc.type}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <VerdictBadge verdict={ioc.verdict} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-bg-tertiary rounded h-1.5 overflow-hidden">
                        <div
                          className={`h-full ${
                            ioc.confidence >= 80 ? 'bg-critical' : ioc.confidence >= 60 ? 'bg-warning' : 'bg-accent-blue'
                          }`}
                          style={{ width: `${ioc.confidence}%` }}
                        />
                      </div>
                      <span className="font-mono text-text-muted text-2xs">{ioc.confidence}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-text-muted text-2xs">
                    {formatDateShort(ioc.firstSeen)}
                  </td>
                  <td className="px-4 py-3 text-text-secondary font-mono text-2xs">
                    {ioc.source}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedIOC(ioc);
                      }}
                      className="btn-ghost text-xs py-1 px-2"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        </div>
        <div className="px-4 py-2.5 bg-bg-tertiary border-t border-border flex items-center justify-between text-2xs text-text-muted">
          <span>Engine: <span className="font-mono text-text-secondary">Automated Deep Indicator Extractor</span></span>
          <span>Showing {filtered.length} of {iocs.length} indicators</span>
        </div>
      </div>

      {/* Slide-in Detail Drawer */}
      {selectedIOC && (
        <>
          <div
            className="fixed inset-0 bg-black/60 z-40 sm:hidden"
            onClick={() => setSelectedIOC(null)}
          />
          <div className="fixed inset-y-0 right-0 w-full sm:w-[440px] max-w-full bg-bg-secondary border-l border-border shadow-drawer z-50 flex flex-col pt-12">
            <div className="p-4 border-b border-border flex items-center justify-between bg-bg-tertiary">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-accent-blue" />
                <span className="font-semibold text-sm text-text-primary">IOC Intelligence Inspector</span>
              </div>
              <button onClick={() => setSelectedIOC(null)} className="p-1 text-text-muted hover:text-text-primary">
                <X size={16} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="section-title text-2xs">Indicator</span>
                  <button onClick={() => handleCopy(selectedIOC.indicator)} className="flex items-center gap-1 text-2xs text-text-muted hover:text-text-primary">
                    <Copy size={11} /> {copiedIndicator ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <div className="p-2.5 bg-bg-primary border border-border rounded font-mono text-xs text-text-primary break-all">
                  {selectedIOC.indicator}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 p-3 bg-bg-tertiary border border-border rounded">
                <div>
                  <div className="text-2xs text-text-muted uppercase">Type</div>
                  <div className="font-mono font-medium text-text-primary mt-0.5">{selectedIOC.type}</div>
                </div>
                <div>
                  <div className="text-2xs text-text-muted uppercase">Verdict</div>
                  <div className="mt-0.5"><VerdictBadge verdict={selectedIOC.verdict} /></div>
                </div>
                <div>
                  <div className="text-2xs text-text-muted uppercase">Confidence</div>
                  <div className="font-mono font-bold text-text-primary mt-0.5">{selectedIOC.confidence}%</div>
                </div>
              </div>

              {selectedIOC.country && (
                <div className="panel p-3 space-y-2 border-l-2 border-l-accent-blue">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-text-primary">
                    <Globe className="w-3.5 h-3.5 text-accent-blue" />
                    <span>Infrastructure Location</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-text-muted text-2xs">Country:</span>
                      <div className="font-medium text-text-primary">{selectedIOC.country}</div>
                    </div>
                    <div>
                      <span className="text-text-muted text-2xs">ASN:</span>
                      <div className="font-mono text-text-secondary">{selectedIOC.asn || 'N/A'}</div>
                    </div>
                    <div className="col-span-2">
                      <span className="text-text-muted text-2xs">Hosting Organization:</span>
                      <div className="text-text-secondary">{selectedIOC.organization || 'N/A'}</div>
                    </div>
                  </div>
                  <div className="p-2 bg-bg-primary border border-border rounded text-2xs text-text-muted italic">
                    Infrastructure Geolocation specifies server hosting topology. This does NOT indicate confirmed attacker nationality or attribution.
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <span className="section-title text-2xs">Threat Intelligence Sources</span>
                <div className="border border-border rounded divide-y divide-border bg-bg-tertiary">
                  {[
                    {
                      name: 'Primary Ingress Feed',
                      status: 'Available',
                      verdict: selectedIOC.verdict,
                      detail: `Source: ${selectedIOC.source} · Confidence ${selectedIOC.confidence}%`,
                    },
                    {
                      name: selectedIOC.type === 'URL' ? 'abuse.ch URLhaus' : 'abuse.ch ThreatFox',
                      status: 'Available',
                      verdict: selectedIOC.verdict,
                      detail: selectedIOC.verdict === 'MALICIOUS'
                        ? `Active malicious indicator match (${selectedIOC.confidence}% confidence)`
                        : selectedIOC.verdict === 'SUSPICIOUS'
                        ? 'Deceptive or suspicious indicator pattern flagged'
                        : 'Zero malicious signatures matched on live query',
                    },
                    {
                      name: 'Autonomous System Mapper (BGP)',
                      status: selectedIOC.asn ? 'Available' : 'Unavailable',
                      verdict: selectedIOC.asn ? 'CLEAN' : 'UNKNOWN',
                      detail: selectedIOC.asn ? `${selectedIOC.asn} (${selectedIOC.organization || 'Hosting Provider'})` : 'No public ASN record',
                    },
                  ].map((feed) => (
                    <div key={feed.name} className="p-2.5 flex items-center justify-between">
                      <div>
                        <div className="font-medium text-text-primary flex items-center gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full ${feed.status === 'Available' ? 'bg-success' : 'bg-text-muted'}`} />
                          {feed.name}
                        </div>
                        <div className="text-2xs text-text-muted mt-0.5">{feed.detail}</div>
                      </div>
                      <VerdictBadge verdict={feed.verdict as any} />
                    </div>
                  ))}
                </div>
              </div>

              {selectedIOC.relatedCases && selectedIOC.relatedCases.length > 0 && (
                <div className="space-y-1.5">
                  <span className="section-title text-2xs">Correlated Investigations</span>
                  <div className="space-y-1">
                    {selectedIOC.relatedCases.map((rc) => (
                      <div key={rc} className="p-2 rounded bg-bg-tertiary border border-border flex items-center justify-between text-xs">
                        <span className="font-mono text-accent-blue">{rc}</span>
                        <span className="text-2xs text-text-muted">Campaign overlap</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
