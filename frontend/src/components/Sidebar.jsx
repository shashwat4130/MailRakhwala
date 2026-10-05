import React, { useState, useEffect } from 'react';

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

  ChevronLeft,

  ChevronRight,

  X,

} from 'lucide-react';

import { useAnalysisContext } from '../context/AnalysisContext';

import MailRakhwalaLogo from './MailRakhwalaLogo';



export const primaryNavigation = [

  { label: 'Home', href: '/', icon: Home, isGlobal: true },

  { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },

  { label: 'Stream Analysis', href: '/streams', icon: Network },

  { label: 'TLS Analysis', href: '/tls', icon: LockKeyhole },

  { label: 'Evidence Explorer', href: '/evidence', icon: Search },

  { label: 'Findings & CVEs', href: '/findings', icon: AlertTriangle },

  { label: 'Security Posture', href: '/posture', icon: ShieldCheck },

  { label: 'Risk Intelligence', href: '/risk-intelligence', icon: Compass },

  { label: 'Forensic Reports', href: '/reports', icon: FileText },

];



export const isItemActive = (href, pathname) => {

  if (href === '/' && pathname === '/') return true;

  if ((href === '/streams' || href === '/analysis') && (pathname === '/streams' || pathname === '/analysis' || pathname === '/stream-analysis')) return true;

  if ((href === '/tls' || href === '/tls-analysis') && (pathname === '/tls' || pathname === '/tls-analysis')) return true;

  if (href === '/evidence' && (pathname === '/evidence' || pathname === '/evidence-explorer')) return true;

  if (href === '/findings' && pathname === '/findings') return true;

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

  return false;

};



export function NavContent({ onClose, collapsed = false, onToggleCollapse }) {

  const location = useLocation();

  const { analysisId } = useAnalysisContext();

  const hasActiveCapture = Boolean(

    analysisId ||

    (typeof window !== 'undefined' && (localStorage.getItem('active_analysis_id') || localStorage.getItem('analysis_id')))

  );



  return (

    <div className="flex h-full w-full flex-col bg-[#111111] text-white select-none">

      <div className={`flex h-[72px] shrink-0 items-center border-b border-[#202020] px-3.5 transition-all ${collapsed ? 'justify-center' : 'justify-between'

        }`}>

        {collapsed ? (

          onToggleCollapse && (

            <button

              type="button"

              onClick={onToggleCollapse}

              title="Expand sidebar"

              aria-label="Expand sidebar"

              className="group hidden lg:flex h-10 w-10 items-center justify-center rounded-xl bg-[#181818] border border-[#282828] text-neutral-300 hover:text-white hover:bg-[#222222] hover:border-[#383838] transition shadow-sm"

            >

              <ChevronRight className="h-5 w-5 transition-transform group-hover:translate-x-0.5" />

            </button>

          )

        ) : (

          <>

            <NavLink

              to="/"

              onClick={onClose}

              className="focus:outline-none"

              title="MailRakhwala Forensic Console"

            >

              <MailRakhwalaLogo variant="dark" collapsed={false} />

            </NavLink>



            <div className="flex items-center gap-1.5">

              {onToggleCollapse && (

                <button

                  type="button"

                  onClick={onToggleCollapse}

                  title="Collapse sidebar"

                  aria-label="Collapse sidebar"

                  className="hidden lg:flex h-8 w-8 items-center justify-center rounded-lg bg-[#181818] border border-[#282828] text-neutral-400 hover:text-white hover:bg-[#222222] hover:border-[#333333] transition"

                >

                  <ChevronLeft className="h-4 w-4" />

                </button>

              )}

              {onClose && (

                <button

                  type="button"

                  onClick={onClose}

                  className="flex h-8 w-8 items-center justify-center rounded-lg bg-[#202020] text-neutral-400 hover:text-white transition lg:hidden"

                  aria-label="Close sidebar"

                >

                  <X className="h-4 w-4" />

                </button>

              )}

            </div>

          </>

        )}

      </div>



      <nav className="flex-1 overflow-y-auto px-2.5 py-4">

        {!collapsed && (
          <div className="px-3 pb-2 pt-1 text-[9px] font-extrabold uppercase tracking-[0.18em] text-neutral-400 whitespace-nowrap">
            ANALYSIS
          </div>
        )}

        <div className="space-y-1">
          {primaryNavigation
            .filter((item) =>
              ['/', '/dashboard', '/streams', '/tls', '/evidence'].includes(item.href)
            )
            .map((item) => {
              const { label, href, icon: Icon } = item;
              const active = href ? isItemActive(href, location.pathname) : false;

              return (
                <NavLink
                  key={href}
                  to={href}
                  onClick={onClose}
                  title={collapsed ? label : undefined}
                  className={`group relative flex items-center rounded-lg transition-all duration-150 ${collapsed
                      ? 'h-10 w-10 justify-center mx-auto'
                      : 'w-full gap-3 px-3 py-2.5 text-xs font-semibold'
                    } ${active
                      ? 'bg-[#222222] text-white shadow-sm'
                      : 'text-neutral-400 hover:bg-[#181818] hover:text-white'
                    }`}
                >
                  {active && (
                    <span className="absolute left-0 top-1/2 -translate-y-1/2 h-5 w-[3px] rounded-r bg-white" />
                  )}

                  <Icon
                    className={`shrink-0 transition-colors ${active ? 'text-white' : 'text-neutral-400 group-hover:text-white'
                      } ${collapsed ? 'h-4.5 w-4.5' : 'h-4 w-4'}`}
                    strokeWidth={active ? 2.2 : 1.8}
                  />

                  {!collapsed && (
                    <div className="flex flex-1 items-center min-w-0">
                      <span className="truncate whitespace-nowrap">{label}</span>
                    </div>
                  )}
                </NavLink>
              );
            })}
        </div>

        {!collapsed && (
          <div className="mt-4 border-t border-[#202020] pt-4">
            <div className="px-3 pb-2 text-[9px] font-extrabold uppercase tracking-[0.18em] text-neutral-500 whitespace-nowrap">
              SECURITY INTELLIGENCE
            </div>
          </div>
        )}

        <div className="space-y-1">
          {primaryNavigation
            .filter((item) =>
              ['/findings', '/posture', '/risk-intelligence'].includes(item.href)
            )
            .map((item) => {
              const { label, href, icon: Icon } = item;
              const active = href ? isItemActive(href, location.pathname) : false;

              return (
                <NavLink
                  key={href}
                  to={href}
                  onClick={onClose}
                  title={collapsed ? label : undefined}
                  className={`group relative flex items-center rounded-lg transition-all duration-150 ${collapsed
                      ? 'h-10 w-10 justify-center mx-auto'
                      : 'w-full gap-3 px-3 py-2.5 text-xs font-semibold'
                    } ${active
                      ? 'bg-[#222222] text-white shadow-sm'
                      : 'text-neutral-400 hover:bg-[#181818] hover:text-white'
                    }`}
                >
                  {active && (
                    <span className="absolute left-0 top-1/2 -translate-y-1/2 h-5 w-[3px] rounded-r bg-white" />
                  )}

                  <Icon
                    className={`shrink-0 transition-colors ${active ? 'text-white' : 'text-neutral-400 group-hover:text-white'
                      } ${collapsed ? 'h-4.5 w-4.5' : 'h-4 w-4'}`}
                    strokeWidth={active ? 2.2 : 1.8}
                  />

                  {!collapsed && (
                    <div className="flex flex-1 items-center min-w-0">
                      <span className="truncate whitespace-nowrap">{label}</span>
                    </div>
                  )}
                </NavLink>
              );
            })}
        </div>

        {!collapsed && (
          <div className="mt-4 border-t border-[#202020] pt-4">
            <div className="px-3 pb-2 text-[9px] font-extrabold uppercase tracking-[0.18em] text-neutral-500 whitespace-nowrap">
              REPORTING
            </div>
          </div>
        )}

        <div className="space-y-1">
          {primaryNavigation
            .filter((item) => item.href === '/reports')
            .map((item) => {
              const { label, href, icon: Icon } = item;
              const active = href ? isItemActive(href, location.pathname) : false;

              return (
                <NavLink
                  key={href}
                  to={href}
                  onClick={onClose}
                  title={collapsed ? label : undefined}
                  className={`group relative flex items-center rounded-lg transition-all duration-150 ${collapsed
                      ? 'h-10 w-10 justify-center mx-auto'
                      : 'w-full gap-3 px-3 py-2.5 text-xs font-semibold'
                    } ${active
                      ? 'bg-[#222222] text-white shadow-sm'
                      : 'text-neutral-400 hover:bg-[#181818] hover:text-white'
                    }`}
                >
                  {active && (
                    <span className="absolute left-0 top-1/2 -translate-y-1/2 h-5 w-[3px] rounded-r bg-white" />
                  )}

                  <Icon
                    className={`shrink-0 transition-colors ${active ? 'text-white' : 'text-neutral-400 group-hover:text-white'
                      } ${collapsed ? 'h-4.5 w-4.5' : 'h-4 w-4'}`}
                    strokeWidth={active ? 2.2 : 1.8}
                  />

                  {!collapsed && (
                    <div className="flex flex-1 items-center min-w-0">
                      <span className="truncate whitespace-nowrap">{label}</span>
                    </div>
                  )}
                </NavLink>
              );
            })}
        </div>

        <div className="pt-4 mt-4 border-t border-[#202020]">

          {!collapsed && (

            <div className="px-3 pb-2 text-[9px] font-extrabold uppercase tracking-[0.18em] text-neutral-400 whitespace-nowrap">

              REFERENCE

            </div>

          )}

          <NavLink

            to="/documentation"

            onClick={onClose}

            title={collapsed ? 'Documentation' : undefined}

            className={({ isActive }) =>

              `group relative flex items-center rounded-lg transition-all duration-150 ${collapsed

                ? 'h-10 w-10 justify-center mx-auto'

                : 'w-full gap-3 px-3 py-2.5 text-xs font-semibold'

              } ${isActive

                ? 'bg-[#222222] text-white shadow-sm'

                : 'text-neutral-400 hover:bg-[#181818] hover:text-white'

              }`

            }

          >

            {({ isActive }) => (

              <>

                {isActive && (

                  <span className="absolute left-0 top-1/2 -translate-y-1/2 h-5 w-[3px] rounded-r bg-white" />

                )}

                <BookOpen

                  className={`shrink-0 transition-colors ${isActive ? 'text-white' : 'text-neutral-400 group-hover:text-white'

                    } ${collapsed ? 'h-4.5 w-4.5' : 'h-4 w-4'}`}

                  strokeWidth={isActive ? 2.2 : 1.8}

                />

                {!collapsed && <span className="truncate whitespace-nowrap">Documentation</span>}

              </>

            )}

          </NavLink>

        </div>

      </nav>



      <div className="shrink-0 border-t border-[#202020] p-3 space-y-2 bg-[#141414]">

        {!collapsed && (

          <div className="rounded-lg border border-[#242424] bg-[#181818] p-2.5">

            <div className="flex items-center justify-between">

              <span className="text-[9px] font-bold uppercase tracking-wider text-neutral-400">

                Engine Status

              </span>

              <span className={`inline-block h-1.5 w-1.5 rounded-full ${hasActiveCapture ? 'bg-emerald-500' : 'bg-neutral-400'

                }`} />

            </div>

            <p className="mt-1 truncate font-mono text-[10px] text-neutral-400">

              {hasActiveCapture

                ? `Active: ${analysisId ? analysisId.slice(0, 10) + '...' : 'Loaded'}`

                : 'Awaiting PCAP'}

            </p>

          </div>

        )}

      </div>

    </div>

  );

}



export default function Sidebar() {

  const location = useLocation();

  const isHome = location.pathname === '/';



  const [collapsed, setCollapsed] = useState(() => {

    if (typeof window !== 'undefined') {

      if (window.location.pathname === '/') return true;

      const saved = localStorage.getItem('mailrakhwala_sidebar_collapsed');

      if (saved !== null) return saved === 'true';

    }

    return isHome;

  });



  useEffect(() => {

    if (isHome) {

      setCollapsed(true);

    }

  }, [isHome]);



  const handleToggleCollapse = () => {

    setCollapsed((prev) => {

      const next = !prev;

      localStorage.setItem('mailrakhwala_sidebar_collapsed', String(next));

      return next;

    });

  };



  return (

    <aside

      className={`hidden sticky top-0 h-screen min-h-screen shrink-0 border-r border-[#202020] bg-[#111111] transition-[width] duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] lg:flex flex-col z-30 ${collapsed ? 'w-[72px]' : 'w-[260px]'

        }`}

    >

      <NavContent

        collapsed={collapsed}

        onToggleCollapse={handleToggleCollapse}

      />

    </aside>

  );

}



export function MobileSidebarDrawer({ isOpen, onClose }) {

  if (!isOpen) return null;



  return (

    <div className="fixed inset-0 z-50 lg:hidden">

      <div

        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"

        onClick={onClose}

        aria-hidden="true"

      />

      <div className="fixed inset-y-0 left-0 flex w-[280px] flex-col border-r border-[#202020] bg-[#111111] shadow-2xl">

        <NavContent onClose={onClose} collapsed={false} />

      </div>

    </div>

  );

}