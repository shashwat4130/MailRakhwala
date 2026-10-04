import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  Home,
  LayoutDashboard,
  Network,
  LockKeyhole,
  Search,
  AlertTriangle,
  ShieldCheck,
  Compass,
  FileText,
  BookOpen,
  X,
} from 'lucide-react';

const primaryNavigation = [
  { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { label: 'Stream Analysis', href: '/analysis', icon: Network },
  { label: 'TLS Analysis', href: '/tls-analysis', icon: LockKeyhole },
  { label: 'Evidence Explorer', href: '/evidence', icon: Search },
  { label: 'Findings & CVEs', href: '/findings', icon: AlertTriangle },
  { label: 'Security Posture', href: '/posture', icon: ShieldCheck },
  { label: 'Risk Intelligence', href: '/risk-intelligence', icon: Compass },
  { label: 'Forensic Reports', href: '/reports', icon: FileText },
];

// Helper to determine active link state across route aliases
const isItemActive = (href, pathname) => {
  if (href === '/analysis' && (pathname === '/analysis' || pathname === '/stream-analysis')) return true;
  if (href === '/evidence' && (pathname === '/evidence' || pathname === '/evidence-explorer')) return true;
  if (href === '/posture' && (pathname === '/posture' || pathname === '/security-posture' || pathname === '/rules' || pathname === '/security-rules')) return true;
  if (href === '/risk-intelligence' && (
    pathname === '/risk-intelligence' ||
    pathname === '/anomaly-detection' ||
    pathname === '/threat-context' ||
    pathname === '/explainability' ||
    pathname === '/ml-explainability' ||
    pathname === '/feature-vector'
  )) return true;
  if (href === '/dashboard' && (pathname === '/dashboard' || pathname === '/analytics' || pathname === '/security-analytics' || pathname === '/settings' || pathname === '/analysis-settings')) return true;
  if (href === '/reports' && (pathname === '/reports' || pathname === '/forensic-reports' || pathname === '/export-evidence')) return true;
  if (href === '/tls-analysis' && pathname === '/tls-analysis') return true;
  return false;
};

function NavContent({ onClose }) {
  const location = useLocation();

  return (
    <div className="flex h-full w-full flex-col">
      {/* Header / Logo */}
      <div className="flex h-[84px] shrink-0 items-center justify-between px-5">
        <NavLink to="/" onClick={onClose} className="relative h-[66px] w-[175px] overflow-visible block" title="MailRakhwala Home">
          <video
            autoPlay
            muted
            loop
            playsInline
            src="/mailrakhwala-logo.mp4"
            className="absolute left-0 top-1/2 h-[92px] w-[180px] -translate-y-1/2 scale-[1.1] object-contain object-left"
            aria-label="MailRakhwala"
          />
        </NavLink>
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-50 text-slate-700 hover:bg-blue-100 hover:text-blue-700 transition lg:hidden"
            aria-label="Close sidebar"
          >
            <X className="h-5 w-5" />
          </button>
        )}
      </div>

      <div className="mx-5 h-px shrink-0 bg-blue-100" />

      {/* Primary Navigation - 8 Core Routes */}
      <nav className="flex-1 overflow-y-auto px-3.5 py-4 space-y-1 scrollbar-thin scrollbar-thumb-blue-100">
        <div className="px-3 pb-1 pt-1 text-[10px] font-extrabold uppercase tracking-[0.16em] text-slate-400">
          Console Navigation
        </div>

        {primaryNavigation.map(({ label, href, icon: Icon }) => {
          const active = isItemActive(href, location.pathname);
          return (
            <NavLink
              key={href}
              to={href}
              onClick={onClose}
              className={`group flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-xs font-semibold transition-all ${
                active
                  ? 'bg-[#0B5ED7]/10 text-[#0B5ED7] shadow-sm font-bold'
                  : 'text-[#192837]/70 hover:bg-[#0B5ED7]/5 hover:text-[#0B5ED7]'
              }`}
            >
              <span
                className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg transition-colors ${
                  active
                    ? 'bg-[#0B5ED7]/15 text-[#0B5ED7]'
                    : 'bg-slate-50 text-slate-500 group-hover:bg-blue-50 group-hover:text-[#0B5ED7]'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
              </span>
              <span className="truncate">{label}</span>
            </NavLink>
          );
        })}

        <div className="pt-4">
          <div className="px-3 pb-1 text-[10px] font-extrabold uppercase tracking-[0.16em] text-slate-400">
            Reference
          </div>
          <NavLink
            to="/documentation"
            onClick={onClose}
            className={({ isActive }) =>
              `group flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-xs font-semibold transition-all ${
                isActive
                  ? 'bg-[#0B5ED7]/10 text-[#0B5ED7] shadow-sm font-bold'
                  : 'text-[#192837]/70 hover:bg-[#0B5ED7]/5 hover:text-[#0B5ED7]'
              }`
            }
          >
            {({ isActive }) => (
              <>
                <span
                  className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg transition-colors ${
                    isActive
                      ? 'bg-[#0B5ED7]/15 text-[#0B5ED7]'
                      : 'bg-slate-50 text-slate-500 group-hover:bg-blue-50 group-hover:text-[#0B5ED7]'
                  }`}
                >
                  <BookOpen className="h-3.5 w-3.5" />
                </span>
                <span className="truncate">Documentation</span>
              </>
            )}
          </NavLink>
        </div>
      </nav>

      {/* Footer info box */}
      <div className="shrink-0 px-4 pb-4 pt-2 border-t border-blue-50">
        <div className="rounded-xl border border-blue-100 bg-blue-50/50 px-3.5 py-2.5">
          <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#0B5ED7]">
            MailRakhwala Console
          </p>
          <p className="mt-0.5 text-[10px] leading-relaxed text-[#192837]/50">
            Passive email cryptographic assessment
          </p>
        </div>
      </div>
    </div>
  );
}

export default function Sidebar() {
  return (
    <aside className="hidden h-screen w-[260px] shrink-0 border-r border-blue-100 bg-white/95 shadow-[8px_0_30px_rgba(15,76,160,0.06)] backdrop-blur-xl lg:flex">
      <NavContent />
    </aside>
  );
}

export function MobileSidebarDrawer({ isOpen, onClose }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 lg:hidden">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />
      {/* Drawer */}
      <div className="fixed inset-y-0 left-0 flex w-[280px] flex-col border-r border-blue-100 bg-white shadow-2xl">
        <NavContent onClose={onClose} />
      </div>
    </div>
  );
}
