import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, FileSearch, ShieldAlert, FileText, UploadCloud } from 'lucide-react';

const navigation = [
  { name: 'Capture Ingestion', href: '/', icon: UploadCloud },
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Stream Analysis', href: '/analysis', icon: FileSearch },
  { name: 'Findings & CVEs', href: '/findings', icon: ShieldAlert },
  { name: 'Forensic Reports', href: '/reports', icon: FileText },
];

export default function Sidebar() {
  return (
    <aside className="w-64 border-r border-gray-800 bg-gray-950/40 p-4 flex flex-col justify-between">
      <div className="space-y-1">
        <div className="text-[11px] font-mono uppercase tracking-wider text-gray-400 px-3 mb-2">
          Forensics Console
        </div>
        {navigation.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.name}
              to={item.href}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900/60'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              <span>{item.name}</span>
            </NavLink>
          );
        })}
      </div>

      <div className="p-3 border border-gray-800 rounded-lg bg-gray-900/40 text-xs font-mono text-gray-400 space-y-1">
        <div className="text-gray-300 font-sans font-medium">Standards Baseline</div>
        <div>NIST SP 800-52r2</div>
        <div>RFC 8996 / RFC 8446</div>
      </div>
    </aside>
  );
}