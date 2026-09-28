import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Home,
  LayoutDashboard,
  Network,
  AlertTriangle,
  FileText,
  BookOpen,
} from 'lucide-react';

const navItems = [
  {
    label: 'Home',
    href: '/',
    icon: Home,
  },
  {
    label: 'Dashboard',
    href: '/dashboard',
    icon: LayoutDashboard,
  },
  {
    label: 'Stream Analysis',
    href: '/analysis',
    icon: Network,
  },
  {
    label: 'Findings & CVEs',
    href: '/findings',
    icon: AlertTriangle,
  },
  {
    label: 'Forensic Reports',
    href: '/reports',
    icon: FileText,
  },
  {
    label: 'Documentation',
    href: '/documentation',
    icon: BookOpen,
  },
];

export default function Sidebar() {
  return (
    <aside className="hidden h-screen w-[250px] shrink-0 border-r border-blue-100 bg-white/95 shadow-[8px_0_30px_rgba(15,76,160,0.06)] backdrop-blur-xl lg:flex">
      <div className="flex h-full w-full flex-col">

        {/* Logo */}
        <div className="flex h-[92px] items-center px-5">
          <div className="relative h-[66px] w-[175px] overflow-visible">
            <video
              autoPlay
              muted
              loop
              playsInline
              src="/mailrakhwala-logo.mp4"
              className="absolute left-0 top-1/2 h-[92px] w-[180px] -translate-y-1/2 scale-[1.1] object-contain object-left"
              aria-label="MailRakhwala"
            />
          </div>
        </div>

        <div className="mx-5 h-px bg-blue-100" />

        {/* Navigation */}
        <nav className="flex flex-1 flex-col gap-1.5 px-4 py-6">
          {navItems.map(({ label, href, icon: Icon }) => (
            <NavLink
              key={href}
              to={href}
              end={href === '/'}
              className={({ isActive }) =>
                `group flex w-full items-center gap-3 rounded-xl px-4 py-3 text-sm font-semibold transition-all ${
                  isActive
                    ? 'bg-[#0B5ED7]/10 text-[#0B5ED7] shadow-sm'
                    : 'text-[#192837]/65 hover:bg-[#0B5ED7]/5 hover:text-[#0B5ED7]'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <span
                    className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition-colors ${
                      isActive
                        ? 'bg-[#0B5ED7]/10 text-[#0B5ED7]'
                        : 'bg-slate-50 text-slate-500 group-hover:bg-blue-50 group-hover:text-[#0B5ED7]'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                  </span>

                  <span>{label}</span>
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-5 pb-6">
          <div className="rounded-2xl border border-blue-100 bg-blue-50/50 px-4 py-3">
            <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#0B5ED7]">
              MailRakhwala
            </p>
            <p className="mt-1 text-[11px] leading-relaxed text-[#192837]/50">
              Email security intelligence for captured traffic.
            </p>
          </div>
        </div>
      </div>
    </aside>
  );
}
