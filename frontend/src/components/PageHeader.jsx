import React from 'react';
import { ArrowLeft, TerminalSquare } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function PageHeader({
  category = 'Security Intelligence',
  title,
  description,
  session,
  actions,
  backTo = '/dashboard',
  backLabel = 'Back to dashboard',
}) {
  const navigate = useNavigate();

  return (
    <div className="mb-8 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
      <div>
        {backTo && (
          <button
            type="button"
            onClick={() => navigate(backTo)}
            className="mb-4 inline-flex items-center gap-2 text-xs font-bold text-slate-500 transition hover:text-[#0B5ED7]"
          >
            <ArrowLeft className="h-4 w-4" />
            {backLabel}
          </button>
        )}

        <div className="flex items-center gap-2 text-[11px] font-extrabold uppercase tracking-[0.18em] text-[#0B5ED7]">
          <span className="h-1.5 w-1.5 rounded-full bg-[#0B5ED7]" />
          {category}
        </div>

        <h1 className="mt-2 text-3xl font-black tracking-[-0.04em] text-slate-950 sm:text-4xl">
          {title}
        </h1>

        {description && (
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
            {description}
          </p>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        {session && (
          <div className="rounded-2xl border border-blue-100 bg-white/90 px-4 py-2.5 shadow-sm">
            <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
              Active Capture
            </p>
            <p className="mt-0.5 max-w-[240px] truncate text-xs font-bold text-slate-800">
              {session.filename || 'Capture file'}
            </p>
          </div>
        )}
        {actions}
      </div>
    </div>
  );
}
