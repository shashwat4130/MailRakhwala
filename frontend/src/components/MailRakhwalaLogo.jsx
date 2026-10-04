import React from 'react';

export default function MailRakhwalaLogo({
  variant = 'light',
  state = 'idle',
  collapsed = false,
  className = '',
  size = 'md',
}) {
  const animationClass =
    state === 'analyzing'
      ? 'animate-flame-analyzing'
      : state === 'complete'
      ? 'animate-flame-settle'
      : state === 'idle'
      ? 'animate-flame-idle'
      : '';

  if (collapsed) {
    return (
      <div
        className={`relative flex items-center justify-center ${className}`}
        title="MailRakhwala Forensic Console"
      >
        <div className={`relative flex items-center justify-center h-10 w-10 rounded-xl ${
          variant === 'dark' ? 'bg-[#1C1C1C] border border-[#2A2A2A]' : 'bg-[#EAEAEA] border border-[#D5D5D0]'
        } shadow-sm overflow-hidden`}>
          <div className={`${animationClass} flex items-center justify-center`}>
            <svg
              className={`w-6 h-6 ${variant === 'dark' ? 'text-white' : 'text-[#111111]'}`}
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M12 2L4 5.5V11.5C4 16.5 7.4 21.1 12 22.5C16.6 21.1 20 16.5 20 11.5V5.5L12 2Z"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="opacity-80"
              />
              <path
                d="M12 7C12 7 9.5 9.5 9.5 12C9.5 13.38 10.62 14.5 12 14.5C13.38 14.5 14.5 13.38 14.5 12C14.5 10 13.5 8.5 12 7Z"
                fill="currentColor"
                className={variant === 'dark' ? 'opacity-95' : 'opacity-90'}
              />
              <path
                d="M12 10.5C11.5 11.2 11.2 11.8 11.2 12.3C11.2 12.8 11.6 13.2 12 13.2C12.4 13.2 12.8 12.8 12.8 12.3C12.8 11.8 12.4 11.2 12 10.5Z"
                fill={variant === 'dark' ? '#111111' : '#FFFFFF'}
              />
            </svg>
          </div>
        </div>
      </div>
    );
  }

  if (size === 'hero') {
    return (
      <div className={`relative flex flex-col items-center justify-center select-none ${className}`}>
        <div className={`relative flex items-center justify-center ${animationClass}`}>
          <div className="relative w-[clamp(300px,min(55vw,86vh),800px)] aspect-[3.15/1] flex items-center justify-center overflow-hidden">
            <video
              autoPlay
              muted
              loop
              playsInline
              src="/mailrakhwala-logo.mp4"
              className="h-full w-full object-contain mix-blend-multiply select-none pointer-events-none"
              aria-label="MailRakhwala Forensic Console"
            />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`relative flex items-center gap-3 ${className}`}>
      {variant === 'dark' ? (
        <div className="flex items-center gap-2.5">
          <div className={`relative flex items-center justify-center h-8 w-8 rounded-lg bg-[#1C1C1C] border border-[#282828] ${animationClass}`}>
            <svg
              className="w-5 h-5 text-white"
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M12 2L4 5.5V11.5C4 16.5 7.4 21.1 12 22.5C16.6 21.1 20 16.5 20 11.5V5.5L12 2Z"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="opacity-70"
              />
              <path
                d="M12 7.2C12 7.2 9.8 9.5 9.8 11.8C9.8 13.1 10.8 14.1 12 14.1C13.2 14.1 14.2 13.1 14.2 11.8C14.2 9.8 13.3 8.5 12 7.2Z"
                fill="currentColor"
                className="opacity-95"
              />
              <path
                d="M12 10.2C11.6 10.8 11.3 11.3 11.3 11.7C11.3 12.1 11.6 12.4 12 12.4C12.4 12.4 12.7 12.1 12.7 11.7C12.7 11.3 12.4 10.8 12 10.2Z"
                fill="#111111"
              />
            </svg>
          </div>
          <div className="flex flex-col">
            <span className="text-[13px] font-black tracking-wider text-white uppercase font-mono">
              MailRakhwala
            </span>
            <span className="text-[9px] font-semibold tracking-[0.16em] text-neutral-400 uppercase">
              Forensic Console
            </span>
          </div>
        </div>
      ) : (
        <div className={`relative flex items-center ${animationClass}`}>
          <div className="h-[46px] w-[155px] relative overflow-hidden flex items-center">
            <video
              autoPlay
              muted
              loop
              playsInline
              src="/mailrakhwala-logo.mp4"
              className="h-full w-full object-contain mix-blend-multiply scale-[1.15]"
              aria-label="MailRakhwala"
            />
          </div>
        </div>
      )}
    </div>
  );
}
