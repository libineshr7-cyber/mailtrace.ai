// ============================================================
// MAILTRACE AI — Responsive Sidebar Navigation
// Responsive drawer for mobile/tablet & fixed sidebar on desktop
// ============================================================
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, FolderSearch, Mail, Shield,
  Globe, GitFork, Clock, FileText, Brain,
  ScrollText, Settings, ChevronRight,
  Activity, Wifi, X
} from 'lucide-react';
import { cn } from '../../utils';

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

const NAV_ITEMS = [
  { label: 'Overview',            to: '/',                    icon: LayoutDashboard },
  { label: 'Investigations',      to: '/investigations',       icon: FolderSearch },
  { label: 'Email Analysis',      to: '/email-analysis',       icon: Mail },
  { label: 'IOC Intelligence',    to: '/ioc-intelligence',     icon: Shield },
  { label: 'Infrastructure',      to: '/infrastructure',       icon: Globe },
  { label: 'Investigation Graph', to: '/graph',                icon: GitFork },
  { label: 'Evidence Timeline',   to: '/timeline',             icon: Clock },
  { label: 'Reports',             to: '/reports',              icon: FileText },
  { label: 'Threat Intelligence', to: '/threat-intelligence',   icon: Brain },
  { label: 'Audit Logs',          to: '/audit-logs',           icon: ScrollText },
  { label: 'Settings',            to: '/settings',             icon: Settings },
];

export default function Sidebar({ isOpen = false, onClose }: SidebarProps) {
  const location = useLocation();

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 h-screen w-56 bg-bg-secondary border-r border-border flex flex-col z-40 select-none transition-transform duration-200 ease-in-out',
        isOpen ? 'translate-x-0 shadow-2xl' : '-translate-x-full lg:translate-x-0'
      )}
    >
      {/* Brand Header */}
      <div className="px-4 py-3.5 border-b border-border flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 bg-accent-blue rounded-sm flex items-center justify-center flex-shrink-0">
            <Shield size={14} className="text-white" />
          </div>
          <div>
            <div className="text-sm font-bold text-text-primary tracking-tight leading-none">
              MAILTRACE <span className="text-accent-blue">AI</span>
            </div>
            <div className="text-[10px] text-text-muted leading-tight mt-1">
              SOC Threat Console
            </div>
          </div>
        </div>

        {/* Mobile close button */}
        <button
          onClick={onClose}
          className="p-1 text-text-muted hover:text-text-primary rounded hover:bg-bg-hover lg:hidden"
          aria-label="Close navigation"
        >
          <X size={16} />
        </button>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 overflow-y-auto py-2 px-2">
        <div className="mb-1 px-2 pt-1">
          <span className="section-title text-[10px] uppercase tracking-wider text-text-muted">
            Modules
          </span>
        </div>
        <ul className="space-y-0.5">
          {NAV_ITEMS.map(({ label, to, icon: Icon }) => {
            const isActive = to === '/'
              ? location.pathname === '/'
              : location.pathname.startsWith(to);

            return (
              <li key={to}>
                <NavLink
                  to={to}
                  onClick={onClose}
                  className={cn(
                    'flex items-center gap-2.5 px-2.5 py-2 rounded text-xs transition-colors group',
                    isActive
                      ? 'bg-accent-blue-muted text-accent-blue-light font-medium'
                      : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover'
                  )}
                >
                  <Icon size={14} className="flex-shrink-0" />
                  <span className="flex-1 truncate text-xs">{label}</span>
                  {isActive && <ChevronRight size={11} className="flex-shrink-0 opacity-60" />}
                </NavLink>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* System Status footer */}
      <div className="flex-shrink-0 border-t border-border px-3.5 py-2.5 space-y-1.5 bg-bg-tertiary/50">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">Status</p>
        <div className="flex items-center gap-2 text-2xs text-text-secondary">
          <span className="w-1.5 h-1.5 rounded-full bg-success flex-shrink-0" />
          <Activity size={10} className="text-success flex-shrink-0" />
          <span className="truncate">Core Engines Nominal</span>
        </div>
        <div className="flex items-center gap-2 text-2xs text-text-secondary">
          <span className="w-1.5 h-1.5 rounded-full bg-success flex-shrink-0" />
          <Wifi size={10} className="text-success flex-shrink-0" />
          <span className="truncate">Threat Feeds Active</span>
        </div>
        <div className="pt-2 border-t border-border flex items-center gap-2">
          <div className="w-5 h-5 rounded-sm bg-bg-secondary border border-border flex items-center justify-center text-[9px] font-semibold text-text-secondary flex-shrink-0">
            SA
          </div>
          <div className="min-w-0">
            <p className="text-2xs font-medium text-text-primary truncate leading-none">Security Analyst</p>
            <p className="text-[9px] text-text-muted leading-none mt-0.5">Tier 3 Responder</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
