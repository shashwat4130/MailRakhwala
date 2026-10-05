import React, { useRef } from 'react';
import { NavLink } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Sparkles,
  PlayCircle,
  FileText,
} from 'lucide-react';
import MailRakhwalaLogo from '../components/MailRakhwalaLogo';
import CaptureConsole from '../components/CaptureConsole';

const easeApple = [0.16, 1, 0.3, 1];

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.06,
      delayChildren: 0.02,
    },
  },
};

const logoVariants = {
  hidden: { opacity: 0, scale: 0.985, y: 8 },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: {
      duration: 0.6,
      ease: easeApple,
    },
  },
};

const itemFadeUp = {
  hidden: { opacity: 0, y: 8 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.5,
      ease: easeApple,
    },
  },
};

const RESOURCE_LINKS = {
  demoVideo: 'https://youtu.be/xcHMo0NGuwM',
  documentation: '/documentation',
};

export default function Home() {
  const captureConsoleRef = useRef(null);

  return (
    <div className="relative min-h-[100dvh] w-full bg-white text-[#111111] py-2 sm:py-2.5 px-3 sm:px-6 lg:px-8 flex flex-col justify-between select-none overflow-x-hidden">

      <div className="relative z-20 w-full flex justify-end items-center gap-2.5 pr-0 sm:pr-2 lg:pr-3 pt-0.5 pb-0">
        <a
          href={RESOURCE_LINKS.demoVideo}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 rounded-lg bg-[#111111] px-4 py-2 sm:px-5 sm:py-2.5 text-xs sm:text-sm font-semibold text-white shadow-xs transition-all duration-200 hover:-translate-y-0.5 hover:bg-[#222222] hover:shadow-sm focus:outline-none focus:ring-2 focus:ring-[#111111] focus:ring-offset-2"
        >
          <PlayCircle className="h-4 w-4" />
          <span>Demo Video</span>
        </a>

        <NavLink
          to={RESOURCE_LINKS.documentation}
          className="inline-flex items-center gap-1.5 rounded-lg bg-[#111111] px-4 py-2 sm:px-5 sm:py-2.5 text-xs sm:text-sm font-semibold text-white shadow-xs transition-all duration-200 hover:-translate-y-0.5 hover:bg-[#222222] hover:shadow-sm focus:outline-none focus:ring-2 focus:ring-[#111111] focus:ring-offset-2"
        >
          <FileText className="h-4 w-4" />
          <span>Documentation</span>
        </NavLink>
      </div>

      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="relative z-10 w-full max-w-[1080px] mx-auto flex-1 flex flex-col items-center justify-center text-center my-auto -mt-2 sm:-mt-6 px-2 sm:px-4"
      >
        <motion.div
          variants={logoVariants}
          className="w-full flex flex-col items-center justify-center mb-0 sm:mb-0.5 -mt-1 sm:-mt-2.5"
        >
          <MailRakhwalaLogo
            variant="light"
            size="hero"
            state="idle"
          />
        </motion.div>

        <motion.div variants={itemFadeUp} className="mb-1">
          <div className="inline-flex items-center gap-1.5 rounded-full border border-[#E5E5E0] bg-white px-3 py-0.5 text-[10px] sm:text-[11px] font-bold uppercase tracking-[0.16em] text-[#555555] shadow-xs">
            <Sparkles className="h-3 w-3 text-[#111111]" />
            CRYPTOGRAPHIC TELEMETRY &amp; COMPLIANCE AUDIT
          </div>
        </motion.div>

        <motion.div variants={itemFadeUp} className="max-w-[700px] px-2">
          <h1 className="text-[clamp(1.35rem,2.7vw,2.3rem)] font-black tracking-tight text-[#111111] leading-[1.12]">
            Passive Email Cryptographic Posture &amp; Risk Forensics
          </h1>
        </motion.div>

        <motion.div variants={itemFadeUp} className="mt-1.5 max-w-[600px] px-3">
          <p className="text-xs sm:text-[13px] md:text-sm leading-snug sm:leading-relaxed text-[#666666]">
            Inspect captured email traffic without decryption and audit TLS, certificates,
            and cryptographic posture against 19 deterministic security rules.
          </p>
        </motion.div>

        <motion.div
          id="capture-section"
          variants={itemFadeUp}
          className="w-full max-w-[600px] mt-2.5 sm:mt-3"
        >
          <CaptureConsole ref={captureConsoleRef} />
        </motion.div>
      </motion.div>

      <footer className="relative z-10 mt-auto pt-2 pb-1 border-t border-[#E5E5E0] w-full max-w-[760px] mx-auto flex items-center justify-center text-[10px] sm:text-xs text-[#888888]">
        <div className="flex items-center gap-2">
          <span className="h-1.5 w-1.5 rounded-full bg-[#111111]" />
          <span>MailRakhwala Cryptographic Forensic Console</span>
        </div>
      </footer>
    </div>
  );
}