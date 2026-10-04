import React from 'react';
import { useNavigate } from 'react-router-dom';
import { TerminalSquare, Upload } from 'lucide-react';

export default function EmptyAnalysisState({
  title = 'No active analysis',
  description = 'Upload a PCAP or PCAPNG capture first to view forensic analysis and intelligence.',
  buttonText = 'Capture Ingestion',
}) {
  const navigate = useNavigate();

  return (
    <div className="flex min-h-[65vh] items-center justify-center p-6">
      <div className="w-full max-w-lg rounded-3xl border border-blue-100 bg-white p-8 text-center shadow-[0_18px_55px_rgba(15,76,160,0.08)]">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-50 text-[#0B5ED7]">
          <TerminalSquare className="h-7 w-7" />
        </div>
        <h2 className="mt-5 text-2xl font-black tracking-tight text-slate-900">
          {title}
        </h2>
        <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">
          {description}
        </p>
        <button
          type="button"
          onClick={() => navigate('/')}
          className="mt-6 inline-flex items-center gap-2 rounded-xl bg-[#0B5ED7] px-6 py-3 text-sm font-bold text-white shadow-lg shadow-[0_8px_24px_rgba(11,94,215,0.20)] transition hover:bg-[#084FB8] active:scale-[0.98]"
        >
          <Upload className="h-4 w-4" />
          {buttonText}
        </button>
      </div>
    </div>
  );
}
