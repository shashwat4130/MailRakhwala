import React from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, Shield, ArrowRight } from 'lucide-react';

/**
 * StartAnalysisState / EmptyAnalysisState
 * 
 * Consistent, authoritative no-capture state for every analysis-dependent page.
 * Avoids showing fake scores, empty charts, or 0 findings when no PCAP has been evaluated.
 */
export default function EmptyAnalysisState({
  title = 'START ANALYSIS',
  description = 'Upload a PCAP to begin email security analysis.',
  buttonText = 'Start Analysis',
  supportingText = 'Mail Rakhwala will reconstruct email streams, audit TLS/PKI, evaluate security rules, and generate evidence-linked intelligence.',
  featureBadge = 'Passive Cryptographic Forensics',
}) {
  const navigate = useNavigate();

  return (
    <div className="flex min-h-[60vh] items-center justify-center p-6 bg-[#F7F7F5]">
      <div className="w-full max-w-lg rounded-2xl border border-[#E5E5E0] bg-white p-8 sm:p-10 text-center shadow-sm">
        {/* Forensic Icon Badge */}
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[#111111] text-white shadow-sm">
          <UploadCloud className="h-6 w-6" strokeWidth={1.8} />
        </div>

        {/* Feature Eyebrow */}
        <div className="mt-5 inline-flex items-center gap-1.5 rounded-full border border-[#E5E5E0] bg-[#F7F7F5] px-3 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-neutral-600">
          <Shield className="h-3 w-3 text-neutral-800" />
          {featureBadge}
        </div>

        {/* Main Title */}
        <h2 className="mt-4 text-2xl font-black tracking-tight text-[#111111]">
          {title}
        </h2>

        {/* Customized Feature Description */}
        <p className="mx-auto mt-2.5 max-w-md text-sm leading-relaxed text-[#666666]">
          {description}
        </p>

        {/* Standard Supporting Text */}
        {supportingText && (
          <p className="mx-auto mt-3 max-w-sm text-xs leading-relaxed text-neutral-400">
            {supportingText}
          </p>
        )}

        {/* Primary Action Button */}
        <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-3">
          <button
            type="button"
            onClick={() => navigate('/')}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-[#111111] px-6 py-3 text-xs font-bold uppercase tracking-wider text-white shadow-sm transition-all hover:bg-[#222222] active:scale-[0.98]"
          >
            <UploadCloud className="h-4 w-4" />
            {buttonText}
            <ArrowRight className="h-3.5 w-3.5 opacity-70" />
          </button>
        </div>
      </div>
    </div>
  );
}
export const StartAnalysisState = EmptyAnalysisState;
