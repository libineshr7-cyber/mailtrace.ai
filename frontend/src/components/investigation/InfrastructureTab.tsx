// ============================================================
// MAILTRACE AI — Infrastructure Tab (Leaflet & OpenStreetMap)
// Geolocation of sending, relay, hosting, and resolution nodes
// ============================================================
import { useState, useEffect } from 'react';
import {
  Globe, Server, MapPin, AlertTriangle, Shield,
  ExternalLink, Network, Info, X
} from 'lucide-react';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import { getInfrastructure } from '../../services/api';
import type { InfrastructurePoint } from '../../types';
import { RiskBadge } from '../ui/Badge';
import { LoadingOverlay, ErrorState } from '../ui/States';

// Fix leaflet marker icon assets
import markerIcon2x from 'leaflet/dist/images/marker-icon-2x.png';
import markerIcon from 'leaflet/dist/images/marker-icon.png';
import markerShadow from 'leaflet/dist/images/marker-shadow.png';

delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: markerIcon2x,
  iconUrl: markerIcon,
  shadowUrl: markerShadow,
});

// Custom colored markers
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

interface Props {
  investigationId: string;
}

export default function InfrastructureTab({ investigationId }: Props) {
  const [points, setPoints] = useState<InfrastructurePoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedPoint, setSelectedPoint] = useState<InfrastructurePoint | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await getInfrastructure(investigationId);
      setPoints(res);
      if (res.length > 0) setSelectedPoint(res[0]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load infrastructure geolocation');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [investigationId]);

  if (loading) return <LoadingOverlay message="Mapping infrastructure geolocation..." />;
  if (error) return <ErrorState message={error} retry={loadData} />;

  return (
    <div className="space-y-4">
      {/* Disclaimer Banner */}
      <div className="p-3 bg-bg-secondary border-l-4 border-l-accent-blue rounded border border-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2.5">
          <Info className="w-4 h-4 text-accent-blue flex-shrink-0" />
          <span className="text-text-secondary">
            <span className="font-semibold text-text-primary">Forensic Infrastructure Attribution Standard: </span>
            Coordinates designate physical and logical hosting servers, proxy relays, and BGP ASNs. This represents <strong className="text-text-primary">Infrastructure Location</strong>, not confirmed threat actor physical origin.
          </span>
        </div>
        <span className="badge bg-bg-tertiary border border-border text-text-muted text-2xs font-mono shrink-0">
          RFC 791 / MaxMind / RDAP
        </span>
      </div>

      {/* Map View */}
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
        <div className="h-[260px] sm:h-[340px] w-full relative z-0">
          <MapContainer
            center={[45, 15]}
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

      {/* Infrastructure Table & Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Table */}
        <div className="lg:col-span-2 panel overflow-hidden">
          <div className="panel-header bg-bg-tertiary flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-text-muted" />
              <span className="text-xs font-semibold uppercase tracking-wider text-text-primary">
                Identified Infrastructure Nodes
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
                {points.map((pt) => (
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
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Node Detail Panel */}
        <div className="panel">
          <div className="panel-header bg-bg-tertiary">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-primary">
              Infrastructure Node Profile
            </span>
          </div>
          {selectedPoint ? (
            <div className="panel-body space-y-3 text-xs">
              <div>
                <div className="text-2xs text-text-muted uppercase">Network Identifier</div>
                <div className="font-mono text-sm font-bold text-text-primary mt-0.5">
                  {selectedPoint.ip || selectedPoint.hostname}
                </div>
                {selectedPoint.hostname && (
                  <div className="font-mono text-2xs text-text-muted mt-0.5">{selectedPoint.hostname}</div>
                )}
              </div>

              <div className="grid grid-cols-2 gap-2 pt-2 border-t border-border">
                <div>
                  <div className="text-2xs text-text-muted">Network Role</div>
                  <div className="badge bg-bg-tertiary text-text-primary mt-0.5">{selectedPoint.role}</div>
                </div>
                <div>
                  <div className="text-2xs text-text-muted">Risk Assessment</div>
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
                <div className="text-2xs text-text-muted uppercase">Autonomous System & Registrar</div>
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
              Select an infrastructure marker or table row to inspect network profile.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
