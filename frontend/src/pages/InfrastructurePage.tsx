// ============================================================
// MAILTRACE AI — Infrastructure Page (Global)
// Cross-investigation infrastructure geolocation & network topology
// ============================================================
import { useState, useEffect } from 'react';
import {
  Globe, Server, MapPin, AlertTriangle, Shield,
  ExternalLink, Network, Info, X, RefreshCw
} from 'lucide-react';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import { getAllInfrastructure } from '../services/api';
import type { InfrastructurePoint } from '../types';
import { RiskBadge } from '../components/ui/Badge';
import { LoadingOverlay } from '../components/ui/States';

// Fix leaflet default icons
import markerIcon2x from 'leaflet/dist/images/marker-icon-2x.png';
import markerIcon from 'leaflet/dist/images/marker-icon.png';
import markerShadow from 'leaflet/dist/images/marker-shadow.png';

delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: markerIcon2x,
  iconUrl: markerIcon,
  shadowUrl: markerShadow,
});

const createCustomMarker = (risk: string) => {
  const color =
    risk === 'CRITICAL' ? '#f85149' :
    risk === 'HIGH' ? '#fb8532' :
    risk === 'MEDIUM' ? '#d29922' : '#3fb950';

  return L.divIcon({
    className: 'custom-leaflet-marker',
    html: `<div style="
      background-color: ${color};
      width: 14px;
      height: 14px;
      border-radius: 50%;
      border: 2px solid #ffffff;
      box-shadow: 0 0 8px ${color};
    "></div>`,
    iconSize: [14, 14],
    iconAnchor: [7, 7],
  });
};

export default function InfrastructurePage() {
  const [points, setPoints] = useState<InfrastructurePoint[]>([]);
  const [selectedPoint, setSelectedPoint] = useState<InfrastructurePoint | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setLoading(true);
    getAllInfrastructure()
      .then((res) => {
        setPoints(res);
        if (res.length > 0) setSelectedPoint(res[0]);
      })
      .catch((err) => console.error('Failed to load global infrastructure', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, []);

  const stats = {
    totalPoints: points.length,
    countries: new Set(points.map((p) => p.country)).size,
    asns: new Set(points.map((p) => p.asn)).size,
    critical: points.filter((p) => p.riskLevel === 'CRITICAL').length,
  };

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base sm:text-lg font-semibold text-text-primary">Infrastructure</h1>
          <p className="text-xs sm:text-sm text-text-muted mt-0.5">
            Geographic distribution of email transmission and resolution infrastructure across active investigations
          </p>
        </div>
        <button onClick={loadData} className="btn-secondary text-xs flex items-center gap-1">
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          <span>Refresh Map</span>
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 sm:gap-3">
        {[
          { label: 'Infrastructure Nodes', value: stats.totalPoints, color: 'text-text-primary' },
          { label: 'Unique Jurisdictions', value: stats.countries, color: 'text-accent-blue' },
          { label: 'Autonomous Systems', value: stats.asns, color: 'text-text-secondary' },
          { label: 'Critical Risk Nodes', value: stats.critical, color: 'text-critical' },
        ].map((s) => (
          <div key={s.label} className="panel px-3 sm:px-4 py-2 sm:py-2.5 flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-3">
            <span className={`text-base sm:text-lg font-semibold font-mono ${s.color}`}>{s.value}</span>
            <span className="text-2xs sm:text-xs text-text-muted">{s.label}</span>
          </div>
        ))}
      </div>

      {/* Standard Disclaimer */}
      <div className="p-3 bg-bg-secondary border-l-4 border-l-accent-blue rounded border border-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2.5">
          <Info className="w-4 h-4 text-accent-blue flex-shrink-0" />
          <span className="text-text-secondary">
            <span className="font-semibold text-text-primary">Forensic Attribution Guideline: </span>
            Coordinates represent hosting facility and network routing nodes (<strong className="text-text-primary">Infrastructure Location</strong>). They do not represent attacker identity or physical domicile.
          </span>
        </div>
        <span className="badge bg-bg-tertiary border border-border text-text-muted text-2xs font-mono shrink-0">
          RFC 791 / BGP / RDAP
        </span>
      </div>

      {/* Global Map Panel */}
      <div className="panel overflow-hidden">
        <div className="panel-header bg-bg-tertiary flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-accent-blue" />
            <span className="text-xs font-semibold uppercase tracking-wider text-text-primary">
              Global Infrastructure Geolocation Map
            </span>
          </div>
          <span className="text-2xs font-mono text-text-muted">
            Powered by OpenStreetMap & Leaflet
          </span>
        </div>
        <div className="h-[260px] sm:h-[380px] w-full relative z-0">
          {loading && <LoadingOverlay message="Querying global routing coordinates..." />}
          <MapContainer
            center={[40, 10]}
            zoom={2}
            scrollWheelZoom={true}
            style={{ height: '100%', width: '100%', background: '#0d1117' }}
          >
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            {points.map((pt) => (
              <Marker
                key={pt.id}
                position={[pt.latitude, pt.longitude]}
                icon={createCustomMarker(pt.riskLevel)}
                eventHandlers={{
                  click: () => setSelectedPoint(pt),
                }}
              >
                <Popup className="dark-leaflet-popup">
                  <div className="p-1 space-y-1 font-sans text-xs">
                    <div className="font-bold text-gray-900">{pt.ip || pt.hostname}</div>
                    <div className="text-gray-600">{pt.role} · {pt.city}, {pt.country}</div>
                    <div className="font-mono text-gray-700 text-2xs">{pt.asn} ({pt.organization})</div>
                    <div className="font-semibold text-red-600 text-2xs">Risk: {pt.riskLevel}</div>
                  </div>
                </Popup>
              </Marker>
            ))}
          </MapContainer>
        </div>
      </div>

      {/* Nodes Table & Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Table */}
        <div className="lg:col-span-2 panel overflow-hidden">
          <div className="panel-header bg-bg-tertiary flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-text-muted" />
              <span className="text-xs font-semibold uppercase tracking-wider text-text-primary">
                Correlated Infrastructure Indicators
              </span>
            </div>
            <span className="badge bg-bg-secondary border border-border text-text-muted text-2xs font-mono">
              {points.length} NODES
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs min-w-[550px]">
              <thead>
                <tr className="border-b border-border bg-bg-tertiary text-text-muted">
                  <th className="text-left px-3 py-2">IP / Hostname</th>
                  <th className="text-left px-3 py-2">Role</th>
                  <th className="text-left px-3 py-2">Infrastructure Location</th>
                  <th className="text-left px-3 py-2">ASN / Organization</th>
                  <th className="text-right px-3 py-2">Risk</th>
                </tr>
              </thead>
              <tbody>
                {points.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="p-4 text-center text-text-muted">
                      No infrastructure points recorded yet. Ingest an email to map routing infrastructure.
                    </td>
                  </tr>
                ) : (
                  points.map((pt) => (
                    <tr
                      key={pt.id}
                      onClick={() => setSelectedPoint(pt)}
                      className={`border-b border-border table-row-hover ${
                        selectedPoint?.id === pt.id ? 'bg-accent-blue-muted' : ''
                      }`}
                    >
                      <td className="px-3 py-2.5 font-mono text-text-primary">
                        <div className="font-medium text-accent-blue">{pt.ip || '—'}</div>
                        {pt.hostname && <div className="text-2xs text-text-muted">{pt.hostname}</div>}
                      </td>
                      <td className="px-3 py-2.5">
                        <span className="badge bg-bg-tertiary border border-border text-text-secondary text-2xs font-mono">
                          {pt.role}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-text-secondary">
                        {pt.city}, {pt.country}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-2xs text-text-muted">
                        <div>{pt.asn}</div>
                        <div className="text-text-secondary truncate max-w-[140px]">{pt.organization}</div>
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <RiskBadge level={pt.riskLevel} />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Point Inspector */}
        <div className="panel">
          <div className="panel-header bg-bg-tertiary">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-primary">
              Infrastructure Node Profile
            </span>
          </div>
          {selectedPoint ? (
            <div className="panel-body space-y-3 text-xs">
              <div>
                <div className="text-2xs text-text-muted uppercase">Node Identifier</div>
                <div className="font-mono text-sm font-bold text-text-primary mt-0.5">
                  {selectedPoint.ip || selectedPoint.hostname}
                </div>
                {selectedPoint.hostname && (
                  <div className="font-mono text-2xs text-text-muted mt-0.5">{selectedPoint.hostname}</div>
                )}
              </div>

              <div className="grid grid-cols-2 gap-2 pt-2 border-t border-border">
                <div>
                  <div className="text-2xs text-text-muted">Role</div>
                  <div className="badge bg-bg-tertiary text-text-primary mt-0.5">{selectedPoint.role}</div>
                </div>
                <div>
                  <div className="text-2xs text-text-muted">Risk</div>
                  <div className="mt-0.5"><RiskBadge level={selectedPoint.riskLevel} /></div>
                </div>
              </div>

              <div className="space-y-1 pt-2 border-t border-border">
                <div className="text-2xs text-text-muted uppercase">Infrastructure Geolocation</div>
                <div className="text-text-primary font-medium">{selectedPoint.city}, {selectedPoint.region}</div>
                <div className="text-text-secondary">{selectedPoint.country}</div>
                <div className="font-mono text-2xs text-text-muted">
                  Coordinates: {selectedPoint.latitude.toFixed(4)}°, {selectedPoint.longitude.toFixed(4)}°
                </div>
              </div>

              <div className="space-y-1 pt-2 border-t border-border">
                <div className="text-2xs text-text-muted uppercase">BGP ASN & Organization</div>
                <div className="font-mono text-xs text-text-primary">{selectedPoint.asn}</div>
                <div className="text-text-secondary">{selectedPoint.organization}</div>
              </div>

              <div className="pt-2 border-t border-border">
                <div className="text-2xs text-text-muted uppercase mb-1">Intelligence Sources</div>
                <div className="flex flex-wrap gap-1">
                  {selectedPoint.sources.map((s) => (
                    <span key={s} className="badge bg-bg-tertiary border border-border text-text-secondary text-2xs">
                      {s}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="panel-body text-center text-text-muted text-xs py-8">
              Select an infrastructure point to inspect technical network telemetry.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
