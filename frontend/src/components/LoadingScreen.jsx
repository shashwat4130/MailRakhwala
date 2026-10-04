import React from 'react';

/**
 * MailRakhwala Living Flame Emblem
 * Monochrome, calm, subtle breathing and layered inner motion.
 * Anchored base, stable outer contour.
 */
export function LivingFlameMark({ size = 'md', className = '' }) {
  const sizeMap = {
    sm: 'h-10 w-10',
    md: 'h-14 w-14',
    lg: 'h-20 w-20',
  };

  const svgSizeMap = {
    sm: 'w-5 h-5',
    md: 'w-7 h-7',
    lg: 'w-10 h-10',
  };

  return (
    <div
      className={`relative flex items-center justify-center rounded-2xl bg-[#111111] border border-[#222222] shadow-sm select-none ${
        sizeMap[size] || sizeMap.md
      } ${className}`}
    >
      <div className="relative flex items-center justify-center animate-flame-analyzing">
        <svg
          className={`${svgSizeMap[size] || svgSizeMap.md} text-white`}
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

          {/* Layered Outer Flame - Off-white/Charcoal */}
          <path
            d="M12 6.8C12 6.8 9.2 9.4 9.2 12.2C9.2 13.8 10.4 15 12 15C13.6 15 14.8 13.8 14.8 12.2C14.8 9.8 13.6 8.2 12 6.8Z"
            fill="#EAEAE6"
            className="opacity-95"
          />

          {/* Layered Inner Core - Dark Charcoal */}
          <path
            d="M12 10.4C11.5 11.1 11.1 11.6 11.1 12.1C11.1 12.7 11.5 13.1 12 13.1C12.5 13.1 12.9 12.7 12.9 12.1C12.9 11.6 12.5 11.1 12 10.4Z"
            fill="#111111"
            className="animate-flame-inner"
          />
        </svg>
      </div>
    </div>
  );
}

/**
 * Universal Shared LoadingState Component
 * Grayscale only, zero blue, respects prefers-reduced-motion.
 *
 * Variants:
 * - 'page' (default): Centered branded loading experience
 * - 'section': Section-level skeleton
 * - 'cards': Metric/data card shimmer skeleton
 * - 'chart': Chart frame skeleton
 */
export function LoadingState({
  variant = 'page',
  title = 'Forensic Telemetry Engine',
  message = 'Loading cryptographic inspection data...',
  count = 3,
  className = '',
}) {
  // 1. DATA CARD SHIMMER
  if (variant === 'cards') {
    return (
      <div className={`grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-${count} gap-4 ${className}`}>
        {Array.from({ length: count }).map((_, i) => (
          <div
            key={i}
            className="rounded-2xl border border-[#E5E5E0] bg-white p-5 space-y-3 shadow-sm overflow-hidden"
          >
            <div className="h-3.5 w-24 rounded animate-shimmer" />
            <div className="h-8 w-16 rounded animate-shimmer" />
            <div className="h-3 w-32 rounded animate-shimmer opacity-80" />
          </div>
        ))}
      </div>
    );
  }

  // 2. CHART SKELETON
  if (variant === 'chart') {
    return (
      <div
        className={`rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm space-y-5 overflow-hidden ${className}`}
      >
        <div className="flex items-center justify-between">
          <div className="space-y-1.5">
            <div className="h-4 w-40 rounded animate-shimmer" />
            <div className="h-3 w-60 rounded animate-shimmer opacity-70" />
          </div>
          <div className="h-6 w-20 rounded animate-shimmer" />
        </div>

        {/* Chart Bar Columns */}
        <div className="h-48 flex items-end justify-between gap-3 pt-6 border-b border-[#E5E5E0]">
          {[40, 75, 55, 90, 60, 85, 45, 70].map((h, i) => (
            <div key={i} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end">
              <div
                style={{ height: `${h}%` }}
                className="w-full rounded-t bg-[#EAEAE8] animate-pulse"
              />
              <div className="h-2 w-full rounded bg-[#E5E5E0] opacity-50" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  // 3. SECTION SKELETON
  if (variant === 'section') {
    return (
      <div
        className={`rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm space-y-4 overflow-hidden ${className}`}
      >
        <div className="h-4 w-48 rounded animate-shimmer" />
        <div className="h-3 w-72 rounded animate-shimmer opacity-70" />
        <div className="h-24 w-full rounded-xl bg-[#F7F7F5] animate-shimmer" />
      </div>
    );
  }

  // 4. FULL / CENTERED BRANDED PAGE LOADING EXPERIENCE (Default)
  return (
    <div
      className={`flex min-h-[50vh] flex-col items-center justify-center p-8 text-center select-none ${className}`}
    >
      <div className="relative mb-4">
        <LivingFlameMark size="md" />
      </div>

      <div className="space-y-1 max-w-sm">
        <h3 className="text-sm font-black uppercase tracking-wider text-[#111111] font-mono">
          {title}
        </h3>
        <p className="text-xs text-[#666666] leading-relaxed">
          {message}
        </p>
      </div>

      {/* Indeterminate Smooth Grayscale Sweep */}
      <div className="relative mt-5 h-1 w-48 overflow-hidden rounded-full bg-[#E5E5E0]">
        <div className="animate-sweep rounded-full bg-[#111111]" />
      </div>
    </div>
  );
}

export default LoadingState;