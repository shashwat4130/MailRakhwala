import React from 'react';
import { ArrowLeft } from 'lucide-react';
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
    <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between border-b border-[#E5E5E0] pb-5">
      <div>
        {backTo && (
          <button
            type="button"
            onClick={() => navigate(backTo)}
            className="mb-3 inline-flex items-center gap-1.5 text-xs font-semibold text-neutral-500 transition hover:text-[#111111]"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            {backLabel}
          </button>
        )}

        <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.16em] text-neutral-500">
          <span className="h-1.5 w-1.5 rounded-full bg-[#111111]" />
          {category}
        </div>

        <h1 className="mt-1 text-2xl sm:text-3xl font-black tracking-tight text-[#111111]">
          {title}
        </h1>

        {description && (
          <p className="mt-1 max-w-2xl text-xs sm:text-sm leading-relaxed text-[#666666]">
            {description}
          </p>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2.5">
        {session && (
          <div className="rounded-lg border border-[#E5E5E0] bg-white px-3.5 py-2 shadow-sm">
            <p className="text-[9px] font-bold uppercase tracking-wider text-neutral-400">
              Active Capture
            </p>
            <p className="mt-0.5 max-w-[220px] truncate text-xs font-bold text-[#111111]">
              {session.filename || 'Capture file'}
            </p>
          </div>
        )}
        {actions}
      </div>
    </div>
  );
}
