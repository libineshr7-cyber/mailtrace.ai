// ============================================================
// MAILTRACE AI — Responsive TopBar
// Mobile hamburger trigger, responsive search, notifications & profile
// ============================================================
import { useState, useRef, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Search, Bell, ChevronRight, X, User, Menu } from 'lucide-react';
import { search } from '../../services/api';
import { MOCK_NOTIFICATIONS } from '../../data/mockData';
import type { SearchResult, Notification } from '../../types';
import { RiskBadge } from '../ui/Badge';
import { formatRelative } from '../../utils';

interface TopBarProps {
  onToggleMobileMenu?: () => void;
}

const BREADCRUMB_MAP: Record<string, string> = {
  '/': 'Overview',
  '/investigations': 'Investigations',
  '/email-analysis': 'Email Scanner',
  '/ioc-intelligence': 'IOC Repository',
  '/infrastructure': 'Infrastructure Map',
  '/graph': 'Correlation Graph',
  '/timeline': 'Evidence Timeline',
  '/reports': 'Forensic Reports',
  '/threat-intelligence': 'Threat Feeds',
  '/audit-logs': 'Audit Logs',
  '/settings': 'Configuration',
};

export default function TopBar({ onToggleMobileMenu }: TopBarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [showSearch, setShowSearch] = useState(false);
  const [showNotifs, setShowNotifs] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [searching, setSearching] = useState(false);
  const [notifications] = useState<Notification[]>(MOCK_NOTIFICATIONS);
  const searchRef = useRef<HTMLDivElement>(null);
  const notifRef = useRef<HTMLDivElement>(null);

  const unreadCount = notifications.filter((n) => !n.read).length;
  const currentTitle =
    BREADCRUMB_MAP[location.pathname] ||
    (location.pathname.startsWith('/investigation/') ? 'Investigation Case' : 'Console');

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setShowSearch(false);
      }
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifs(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  useEffect(() => {
    if (!query.trim()) {
      setResults([]);
      return;
    }
    const t = setTimeout(async () => {
      setSearching(true);
      const r = await search(query);
      setResults(r);
      setSearching(false);
    }, 300);
    return () => clearTimeout(t);
  }, [query]);

  const notifColors: Record<string, string> = {
    ERROR: 'text-critical',
    WARNING: 'text-warning',
    SUCCESS: 'text-success',
    INFO: 'text-accent-blue',
  };
  const notifDots: Record<string, string> = {
    ERROR: 'bg-critical',
    WARNING: 'bg-warning',
    SUCCESS: 'bg-success',
    INFO: 'bg-accent-blue',
  };

  return (
    <header className="fixed top-0 left-0 lg:left-56 right-0 h-[48px] bg-bg-secondary border-b border-border z-20 flex items-center px-3 sm:px-4 gap-2 sm:gap-4 transition-all duration-200">
      {/* Mobile Hamburger button */}
      <button
        onClick={onToggleMobileMenu}
        className="p-1.5 rounded text-text-secondary hover:text-text-primary hover:bg-bg-hover lg:hidden flex-shrink-0"
        aria-label="Toggle navigation menu"
      >
        <Menu size={18} />
      </button>

      {/* Breadcrumbs / Page Title */}
      <div className="flex items-center gap-1.5 flex-1 min-w-0">
        <span className="text-2xs font-mono text-text-muted hidden sm:inline truncate">MAILTRACE AI</span>
        <ChevronRight size={12} className="text-text-muted hidden sm:inline flex-shrink-0" />
        <span className="text-xs font-semibold text-text-primary truncate">{currentTitle}</span>
      </div>

      {/* Global Quick Search */}
      <div ref={searchRef} className="relative">
        <div className="relative flex items-center">
          <Search size={12} className="absolute left-2.5 text-text-muted pointer-events-none" />
          <input
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setShowSearch(true);
            }}
            onFocus={() => setShowSearch(true)}
            placeholder="Search cases, IOCs..."
            className="w-32 sm:w-60 pl-7 pr-3 py-1.5 text-xs bg-bg-tertiary border border-border rounded text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-blue focus:ring-1 focus:ring-accent-blue transition-all"
          />
          {query && (
            <button
              onClick={() => {
                setQuery('');
                setResults([]);
              }}
              className="absolute right-2 text-text-muted hover:text-text-primary"
            >
              <X size={12} />
            </button>
          )}
        </div>

        {showSearch && query.length > 0 && (
          <div className="absolute top-full mt-1 right-0 w-72 sm:w-80 bg-bg-secondary border border-border rounded shadow-dropdown z-50">
            {searching ? (
              <div className="px-3 py-2 text-xs text-text-muted">Searching repository...</div>
            ) : results.length === 0 ? (
              <div className="px-3 py-2 text-xs text-text-muted">No telemetry found for "{query}"</div>
            ) : (
              <ul className="max-h-60 overflow-y-auto divide-y divide-border">
                {results.map((r) => (
                  <li key={r.id}>
                    <button
                      onClick={() => {
                        setShowSearch(false);
                        setQuery('');
                        if (r.type === 'INVESTIGATION') navigate(`/investigation/${r.id}`);
                        else navigate(`/ioc-intelligence`);
                      }}
                      className="w-full flex items-center gap-2.5 px-3 py-2 hover:bg-bg-hover text-left transition-colors"
                    >
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium text-text-primary truncate">{r.label}</p>
                        {r.subLabel && <p className="text-2xs text-text-muted truncate">{r.subLabel}</p>}
                      </div>
                      {r.riskLevel && <RiskBadge level={r.riskLevel} />}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      {/* Notifications Dropdown */}
      <div ref={notifRef} className="relative">
        <button
          onClick={() => setShowNotifs(!showNotifs)}
          className="relative p-1.5 text-text-secondary hover:text-text-primary hover:bg-bg-hover rounded transition-colors"
          aria-label="View security notifications"
        >
          <Bell size={15} />
          {unreadCount > 0 && (
            <span className="absolute -top-0.5 -right-0.5 w-3.5 h-3.5 bg-critical text-white text-2xs font-bold rounded-full flex items-center justify-center">
              {unreadCount}
            </span>
          )}
        </button>

        {showNotifs && (
          <div className="absolute top-full mt-1 right-0 w-72 sm:w-80 bg-bg-secondary border border-border rounded shadow-dropdown z-50">
            <div className="px-3 py-2 border-b border-border flex items-center justify-between">
              <p className="text-xs font-semibold text-text-primary">Active Security Alerts</p>
              <span className="text-2xs font-mono text-text-muted">{unreadCount} Unread</span>
            </div>
            <ul className="max-h-72 overflow-y-auto divide-y divide-border">
              {notifications.map((n) => (
                <li
                  key={n.id}
                  className={`px-3 py-2.5 hover:bg-bg-hover transition-colors ${
                    !n.read ? 'bg-accent-blue-muted/10' : ''
                  }`}
                >
                  <div className="flex items-start gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 mt-1 ${notifDots[n.type]}`} />
                    <div className="flex-1 min-w-0">
                      <p className={`text-xs font-medium ${notifColors[n.type]}`}>{n.title}</p>
                      <p className="text-2xs text-text-muted mt-0.5 leading-tight">{n.message}</p>
                      <p className="text-[10px] text-text-muted mt-1 font-mono">{formatRelative(n.timestamp)}</p>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Analyst Profile */}
      <div className="relative">
        <button
          onClick={() => setShowProfile(!showProfile)}
          className="flex items-center gap-2 p-1 text-text-secondary hover:text-text-primary hover:bg-bg-hover rounded transition-colors"
          aria-label="User profile menu"
        >
          <div className="w-6 h-6 bg-accent-blue-muted border border-accent-blue-muted rounded-sm flex items-center justify-center text-accent-blue font-semibold text-2xs">
            SA
          </div>
        </button>

        {showProfile && (
          <div className="absolute top-full mt-1 right-0 w-52 bg-bg-secondary border border-border rounded shadow-dropdown z-50">
            <div className="px-3 py-2.5 border-b border-border">
              <p className="text-xs font-semibold text-text-primary">Security Analyst</p>
              <p className="text-2xs text-text-muted font-mono truncate">analyst@mailtrace.internal</p>
            </div>
            <ul className="py-1 text-xs">
              <li>
                <button
                  className="w-full text-left px-3 py-1.5 text-text-secondary hover:bg-bg-hover hover:text-text-primary"
                  onClick={() => {
                    setShowProfile(false);
                    navigate('/settings');
                  }}
                >
                  Platform Settings
                </button>
              </li>
              <li>
                <button
                  className="w-full text-left px-3 py-1.5 text-text-secondary hover:bg-bg-hover hover:text-text-primary"
                  onClick={() => {
                    setShowProfile(false);
                    navigate('/audit-logs');
                  }}
                >
                  Session Audit Logs
                </button>
              </li>
              <li className="border-t border-border mt-1 pt-1">
                <button
                  className="w-full text-left px-3 py-1.5 text-critical hover:bg-bg-hover"
                  onClick={() => {
                    sessionStorage.removeItem('mailtrace_auth');
                    window.location.reload();
                  }}
                >
                  Sign Out
                </button>
              </li>
            </ul>
          </div>
        )}
      </div>
    </header>
  );
}
