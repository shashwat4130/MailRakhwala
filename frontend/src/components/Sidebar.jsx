import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  History,
  Gauge,
  UploadCloud,
} from 'lucide-react';

const navigation = [
  {
    name: 'Upload PCAP',
    href: '/',
    icon: UploadCloud,
  },
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: LayoutDashboard,
  },
  {
    name: 'Analysis History',
    href: '/history',
    icon: History,
  },
  {
    name: 'Score Criteria',
    href: '/score-criteria',
    icon: Gauge,
  },
];

export default function Sidebar() {
  return (
    <aside className="w-64 min-h-screen shrink-0 border-r border-gray-200 bg-white flex flex-col">

      {/* Logo */}
      <div className="px-5 pt-7 pb-8">
        <div className="flex items-center justify-center">
          <video
            src="/mailrakhwala-logo.mp4"
            autoPlay
            muted
            loop
            playsInline
            className="w-44 h-auto object-contain"
          />
        </div>

      
      </div>

      {/* Navigation */}
      <nav className="px-3 space-y-1.5">
        {navigation.map((item) => {
          const Icon = item.icon;

          return (
            <NavLink
              key={item.name}
              to={item.href}
              className={({ isActive }) =>
                `group relative flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all duration-200 ${
                  isActive
                    ? 'bg-purple-50 text-purple-700 border border-purple-100 shadow-sm'
                    : 'text-gray-600 border border-transparent hover:bg-purple-50/60 hover:text-purple-700'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  {isActive && (
                    <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-7 rounded-r-full bg-purple-600" />
                  )}

                  <Icon
                    className={`w-[18px] h-[18px] shrink-0 transition-colors ${
                      isActive
                        ? 'text-purple-600'
                        : 'text-gray-400 group-hover:text-purple-600'
                    }`}
                    strokeWidth={1.8}
                  />

                  <span>{item.name}</span>
                </>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Security Baseline */}
      <div className="mt-auto p-4">
        <div className="border border-purple-100 bg-purple-50/40 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />

            <span className="text-[11px] font-semibold uppercase tracking-wider text-gray-600">
              Security Baseline
            </span>
          </div>

          <div className="space-y-1.5 text-[10px] font-mono text-gray-400">
            <div>NIST SP 800-52r2</div>
            <div>RFC 8996</div>
            <div>RFC 8446</div>
          </div>
        </div>
      </div>

    </aside>
  );
}