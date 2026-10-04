import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Layers,
  Lock,
  ShieldCheck,
  Cpu,
  FileSearch,
} from 'lucide-react';

const STANDARD_STAGES = [
  {
    id: 'prep',
    title: 'Preparing capture',
    subtitle: 'Reassembling network packets and parsing capture headers',
    icon: Layers,
  },
  {
    id: 'streams',
    title: 'Reconstructing email streams',
    subtitle: 'Reassembling TCP sessions & email protocol handshakes (SMTP, IMAP, POP3)',
    icon: Layers,
  },
  {
    id: 'pki',
    title: 'Auditing TLS / PKI',
    subtitle: 'Inspecting handshake ciphers, key exchanges, certificate validity & trust chains',
    icon: Lock,
  },
  {
    id: 'rules',
    title: 'Evaluating security rules',
    subtitle: 'Auditing 19 RFC compliance standards & deterministic score deductions',
    icon: ShieldCheck,
  },
  {
    id: 'ml',
    title: 'Generating risk intelligence',
    subtitle: 'Extracting 19D feature representation & evaluating statistical ML models',
    icon: Cpu,
  },
  {
    id: 'evidence',
    title: 'Preparing forensic evidence',
    subtitle: 'Linking packet traces, cryptographic findings & forensic report artifacts',
    icon: FileSearch,
  },
];

const DEMO_STAGES = [
  {
    id: 'prep',
    title: 'Preparing capture',
    subtitle: 'Extracting bundled RFC compliance and mail protocol capture stream',
    icon: Layers,
  },
  {
    id: 'streams',
    title: 'Reconstructing email streams',
    subtitle: 'Reassembling TCP sessions & email protocol handshakes (SMTP, IMAP, POP3)',
    icon: Layers,
  },
  {
    id: 'pki',
    title: 'Auditing TLS / PKI',
    subtitle: 'Inspecting handshake ciphers, key exchanges & certificate trust chains',
    icon: Lock,
  },
  {
    id: 'rules',
    title: 'Evaluating security rules',
    subtitle: 'Auditing 19 RFC compliance standards & deterministic score deductions',
    icon: ShieldCheck,
  },
  {
    id: 'ml',
    title: 'Generating risk intelligence',
    subtitle: 'Extracting 19D feature representation & evaluating statistical ML models',
    icon: Cpu,
  },
  {
    id: 'evidence',
    title: 'Preparing forensic evidence',
    subtitle: 'Linking packet traces, cryptographic findings & forensic report artifacts',
    icon: FileSearch,
  },
];

export default function AnalysisProgress({
  filename = 'Capture file',
  isDemo = false,
  status = 'analyzing', // 'analyzing' | 'completed' | 'failed'
  errorMessage = null,
  onViewDashboard,
  onRetry,
}) {
  const stages = isDemo ? DEMO_STAGES : STANDARD_STAGES;
  const [currentStageIndex, setCurrentStageIndex] = useState(0);

  useEffect(() => {
    if (status !== 'analyzing') return;

    const interval = setInterval(() => {
      setCurrentStageIndex((prev) => (prev + 1) % stages.length);
    }, 2400);

    return () => clearInterval(interval);
  }, [status, stages.length]);

  const activeStage = stages[currentStageIndex];

  return (
    <div className="w-full max-w-lg mx-auto rounded-2xl border border-[#E5E5E0] bg-white p-7 sm:p-9 shadow-sm select-none">
      {/* Centered Approved Logo with Living Flame */}
      <div className="flex flex-col items-center text-center">
        {/* Logo Shield Frame - Ultra-dark charcoal/black with subtle dimensionality */}
        <div className="relative mb-6 flex h-20 w-20 items-center justify-center rounded-2xl bg-[#111111] shadow-[0_4px_16px_rgba(0,0,0,0.18)] border border-[#222222]">
          {/* Subtle Ambient Pulse Ring (Only during analysis) */}
          {status === 'analyzing' && (
            <div className="absolute inset-0 rounded-2xl bg-[#111111] animate-ping opacity-10 pointer-events-none" />
          )}

          {/* Living Flame - Flame is the animated element, base anchored */}
          <div
            className={`relative flex items-center justify-center ${
              status === 'analyzing'
                ? 'animate-flame-analyzing'
                : status === 'completed'
                ? 'animate-flame-settle'
                : 'animate-flame-idle'
            }`}
          >
            <svg
              className="w-10 h-10 text-white"
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              {/* Stable Outer Shield Contour */}
              <path
                d="M12 2L4 5.5V11.5C4 16.5 7.4 21.1 12 22.5C16.6 21.1 20 16.5 20 11.5V5.5L12 2Z"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="opacity-70"
              />

              {/* Layered Outer Flame - Off-White/Cream */}
              <path
                d="M12 6.6C12 6.6 9.2 9.2 9.2 12.2C9.2 13.8 10.4 15 12 15C13.6 15 14.8 13.8 14.8 12.2C14.8 9.8 13.6 8.2 12 6.6Z"
                fill="#EAEAE6"
                className="opacity-95"
              />

              {/* Layered Inner Core - Dark Charcoal */}
              <path
                d="M12 10.3C11.5 11.0 11.1 11.5 11.1 12.1C11.1 12.7 11.5 13.1 12 13.1C12.5 13.1 12.9 12.7 12.9 12.1C12.9 11.5 12.5 11.0 12 10.3Z"
                fill="#111111"
                className="animate-flame-inner"
              />
            </svg>
          </div>
        </div>

        {/* Stable Header & Stage Typography */}
        {status === 'analyzing' && (
          <div className="space-y-2">
            <h2 className="text-lg sm:text-xl font-black tracking-wider uppercase text-[#111111]">
              ANALYZING CAPTURE
            </h2>
            <p className="truncate text-xs font-mono text-[#666666] max-w-xs mx-auto">
              {filename}
            </p>
          </div>
        )}

        {/* Completed State - Smooth transition (300–700ms) with small check indicator */}
        {status === 'completed' && (
          <motion.div
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
            className="space-y-2"
          >
            <div className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[11px] font-bold uppercase tracking-wider text-emerald-800">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
              <span>{isDemo ? 'Demo analysis complete' : 'Analysis complete'}</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-black tracking-tight text-[#111111]">
              Telemetry &amp; Evidence Ready
            </h2>
            <p className="text-xs text-[#666666] max-w-sm leading-relaxed mx-auto">
              19 RFC security rules, 19D feature vectors, and cryptographic posture scores have been calibrated.
            </p>
          </motion.div>
        )}

        {/* Error State */}
        {status === 'failed' && (
          <div className="space-y-2">
            <div className="inline-flex items-center gap-1.5 rounded-full border border-red-200 bg-red-50 px-3 py-1 text-[11px] font-bold uppercase tracking-wider text-red-700">
              <AlertTriangle className="h-3.5 w-3.5 text-red-600" />
              Analysis Incomplete
            </div>
            <h2 className="text-lg font-bold text-[#111111]">
              Processing Interruption
            </h2>
            <p className="text-xs text-red-600 max-w-md mx-auto">
              {errorMessage || 'An error occurred while evaluating the packet trace.'}
            </p>
          </div>
        )}
      </div>

      {/* Rotating Stage Display (Indeterminate - NO fake percentages) */}
      {status === 'analyzing' && (
        <div className="mt-8 space-y-4">
          {/* Indeterminate Smooth Grayscale Track */}
          <div className="relative h-1 w-full overflow-hidden rounded-full bg-[#E5E5E0]">
            <div className="animate-sweep rounded-full bg-[#111111]" />
          </div>

          {/* Current Analysis Stage Card */}
          <div className="min-h-[64px] rounded-xl border border-[#E5E5E0] bg-[#F7F7F5] p-3.5">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeStage.id}
                initial={{ opacity: 0, y: 5 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -5 }}
                transition={{ duration: 0.3 }}
                className="flex items-start gap-3 text-left"
              >
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-[#111111] text-white">
                  <activeStage.icon className="h-3.5 w-3.5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-[#111111] flex items-center gap-1.5">
                      {activeStage.title}
                      <span className="text-[10px] text-neutral-400">●</span>
                    </span>
                    <span className="font-mono text-[10px] text-neutral-400 font-bold uppercase tracking-wider">
                      Stage {currentStageIndex + 1}/{stages.length}
                    </span>
                  </div>
                  <p className="mt-0.5 text-[11px] text-[#666666] leading-relaxed">
                    {activeStage.subtitle}
                  </p>
                </div>
              </motion.div>
            </AnimatePresence>
          </div>

          {/* Micro Stage Progression Dots */}
          <div className="flex items-center justify-center gap-2 pt-1">
            {stages.map((s, idx) => (
              <span
                key={s.id}
                className={`transition-all duration-300 rounded-full ${
                  idx === currentStageIndex
                    ? 'h-2 w-5 bg-[#111111]'
                    : idx < currentStageIndex
                    ? 'h-1.5 w-1.5 bg-[#888888]'
                    : 'h-1.5 w-1.5 bg-[#D4D4D0]'
                }`}
                title={s.title}
              />
            ))}
          </div>
        </div>
      )}

      {/* Completion CTA: Explicit [ View Dashboard ] Charcoal Button */}
      {status === 'completed' && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.15 }}
          className="mt-6 pt-5 border-t border-[#E5E5E0] space-y-3"
        >
          <button
            type="button"
            onClick={onViewDashboard}
            className="w-full inline-flex items-center justify-center gap-2.5 rounded-xl bg-[#111111] px-6 py-3.5 text-xs font-bold uppercase tracking-wider text-white shadow-sm transition-all hover:bg-[#222222] active:scale-[0.98] focus:outline-none focus:ring-2 focus:ring-[#111111] focus:ring-offset-2"
          >
            <span>View Dashboard</span>
            <ArrowRight className="h-4 w-4" />
          </button>

          <p className="text-center text-[11px] text-neutral-500">
            Open the executive dashboard to view security findings, TLS telemetry, and forensic reports.
          </p>
        </motion.div>
      )}

      {/* Retry CTA if failed */}
      {status === 'failed' && (
        <div className="mt-6 pt-5 border-t border-[#E5E5E0]">
          <button
            type="button"
            onClick={onRetry}
            className="w-full inline-flex items-center justify-center gap-2 rounded-xl border border-[#E5E5E0] bg-white px-5 py-3 text-xs font-bold text-[#111111] hover:bg-[#F7F7F5] transition"
          >
            <RefreshCw className="h-3.5 w-3.5 text-neutral-600" />
            <span>Try Another Capture</span>
          </button>
        </div>
      )}
    </div>
  );
}
