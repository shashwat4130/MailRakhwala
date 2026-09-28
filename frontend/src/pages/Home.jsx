import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ArrowRight,
  FileText,
  FileUp,
  Menu,
  PlayCircle,
  X,
  Upload,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Database,
  Home as HomeIcon,
  LayoutDashboard,
  Network,
  AlertTriangle as FindingsIcon,
  FileText as ReportsIcon,
  BookOpen,
} from 'lucide-react';

import {
  uploadCapture,
  getAnalysisJob,
  setActiveAnalysisId,
} from '../services/api';

const fadeUp = {
  hidden: {
    opacity: 0,
    y: 20,
  },

  visible: (i) => ({
    opacity: 1,
    y: 0,
    transition: {
      delay: i * 0.12,
      duration: 0.55,
      ease: [0.22, 1, 0.36, 1],
    },
  }),
};

// Evaluator resources. Put these files inside frontend/public/.
const RESOURCE_LINKS = {
  demoVideo: 'https://www.youtube.com/watch?v=YOUR_VIDEO_ID',
  documentation: '/mailrakhwala-documentation.pdf',
  demoPcap: '/mailrakhwala-demo.pcap',
};

const menuItem = {
  hidden: {
    opacity: 0,
    x: 20,
  },

  visible: (i) => ({
    opacity: 1,
    x: 0,
    transition: {
      delay: 0.12 + i * 0.08,
      duration: 0.35,
      ease: [0.22, 1, 0.36, 1],
    },
  }),
};

export default function Home() {
  const navigate = useNavigate();

  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [jobStatus, setJobStatus] = useState(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [demoMode, setDemoMode] = useState(false);

  const fileInputRef = useRef(null);

  /* ============================================================
     REAL BACKEND JOB POLLING
     ============================================================ */

  useEffect(() => {
    if (
      !uploadResult?.analysis_id ||
      jobStatus === 'completed' ||
      jobStatus === 'failed'
    ) {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const job = await getAnalysisJob(uploadResult.analysis_id);

        setJobStatus(job.status);

        if (job.status === 'completed') {
          setActiveAnalysisId(uploadResult.analysis_id);
          clearInterval(interval);

          // Demo uses the same completion card as a normal upload.
          // The evaluator can then choose "View Security Dashboard".
        }

        if (job.status === 'failed') {
          clearInterval(interval);
        }
      } catch (err) {
        console.error('Status check failed:', err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [uploadResult, jobStatus, demoMode, navigate]);

  /* ============================================================
     FILE VALIDATION
     ============================================================ */

  const validateAndSelectFile = (selectedFile) => {
    if (!selectedFile) return;

    const fileName = selectedFile.name.toLowerCase();

    if (!fileName.endsWith('.pcap') && !fileName.endsWith('.pcapng')) {
      setErrorMessage('Only .pcap and .pcapng files are supported.');
      setFile(null);
      return;
    }

    setFile(selectedFile);
    setErrorMessage(null);
    setUploadResult(null);
    setJobStatus(null);
    setDemoMode(false);
  };

  const handleFileChange = (event) => {
    const selectedFile = event.target.files?.[0];

    if (selectedFile) {
      validateAndSelectFile(selectedFile);
    }
  };

  /* ============================================================
     DRAG & DROP
     ============================================================ */

  const handleDragOver = (event) => {
    event.preventDefault();
    event.stopPropagation();
    setDragActive(true);
  };

  const handleDragLeave = (event) => {
    event.preventDefault();
    event.stopPropagation();
    setDragActive(false);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    event.stopPropagation();
    setDragActive(false);

    const droppedFile = event.dataTransfer.files?.[0];

    if (droppedFile) {
      validateAndSelectFile(droppedFile);
    }
  };

  /* ============================================================
     REAL UPLOAD
     ============================================================ */

  const handleUpload = async () => {
    if (!file) return;

    setUploading(true);
    setErrorMessage(null);
    setDemoMode(false);

    try {
      const result = await uploadCapture(file);

      setUploadResult(result);
      setJobStatus(result.status || 'queued');
      setActiveAnalysisId(result.analysis_id);
    } catch (err) {
      const message =
        err.response?.data?.detail ||
        'Failed to upload and enqueue capture.';

      setErrorMessage(message);
    } finally {
      setUploading(false);
    }
  };

  /* ============================================================
     EVALUATOR DEMO PCAP
     ============================================================ */

  const handleDemoPcap = async () => {
    if (uploading) return;

    setUploading(true);
    setErrorMessage(null);
    setUploadResult(null);
    setJobStatus(null);
    setDemoMode(true);

    try {
      const response = await fetch(RESOURCE_LINKS.demoPcap);

      if (!response.ok) {
        throw new Error(
          'Demo PCAP is not available yet. Add mailrakhwala-demo.pcap to frontend/public/.'
        );
      }

      const blob = await response.blob();
      const demoFile = new File(
        [blob],
        'mailrakhwala-demo.pcap',
        { type: 'application/vnd.tcpdump.pcap' }
      );

      const result = await uploadCapture(demoFile);

      setFile(demoFile);
      setUploadResult(result);
      setJobStatus(result.status || 'queued');
      setActiveAnalysisId(result.analysis_id);
    } catch (err) {
      console.error('Demo PCAP failed:', err);
      setErrorMessage(
        err?.message ||
          err?.response?.data?.detail ||
          'The evaluator demo could not be started.'
      );
    } finally {
      setUploading(false);
    }
  };

  /* ============================================================
     RESET
     ============================================================ */

  const handleReset = () => {
    setFile(null);
    setUploadResult(null);
    setErrorMessage(null);
    setJobStatus(null);
    setDemoMode(false);
    setActiveAnalysisId(null);

    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  /* ============================================================
     HELPERS
     ============================================================ */

  const formatFileSize = (bytes) => {
    if (!bytes) return '0 KB';

    const kb = bytes / 1024;

    if (kb < 1024) {
      return `${kb.toFixed(1)} KB`;
    }

    return `${(kb / 1024).toFixed(2)} MB`;
  };

  const isProcessing =
    Boolean(uploadResult) &&
    jobStatus !== 'completed' &&
    jobStatus !== 'failed';

  return (
    <div className="relative h-[100dvh] w-full overflow-hidden bg-[#f8fbff] text-[#192837]">

      {/* ========================================================
          STATIC BLUE GLASS ATMOSPHERE
          No background video — the animated MailRakhwala logo
          remains the visual centerpiece.
          ======================================================== */}

      <div className="absolute inset-0 bg-white" />

      {/* Blue atmosphere stays at the edges. The center remains white so the
          logo's white background visually melts into the page. */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <motion.div
          className="absolute -left-[22%] -top-[20%] h-[62vh] w-[58vw] rounded-full bg-blue-300/18 blur-[125px]"
          animate={{ x: [0, 20, 0], y: [0, 14, 0], scale: [1, 1.035, 1] }}
          transition={{ duration: 16, repeat: Infinity, ease: 'easeInOut' }}
        />

        <motion.div
          className="absolute -right-[22%] -top-[12%] h-[58vh] w-[55vw] rounded-full bg-cyan-300/16 blur-[130px]"
          animate={{ x: [0, -20, 0], y: [0, 16, 0], scale: [1, 1.04, 1] }}
          transition={{ duration: 18, repeat: Infinity, ease: 'easeInOut' }}
        />

        <motion.div
          className="absolute -left-[18%] bottom-[-25%] h-[58vh] w-[58vw] rounded-full bg-blue-300/14 blur-[135px]"
          animate={{ x: [0, 18, 0], y: [0, -12, 0] }}
          transition={{ duration: 20, repeat: Infinity, ease: 'easeInOut' }}
        />

        <motion.div
          className="absolute -right-[18%] bottom-[-22%] h-[55vh] w-[55vw] rounded-full bg-cyan-300/13 blur-[135px]"
          animate={{ x: [0, -18, 0], y: [0, -10, 0] }}
          transition={{ duration: 21, repeat: Infinity, ease: 'easeInOut' }}
        />

        {/* Clean white center / logo quiet zone */}
        <div className="absolute inset-[8%] rounded-[45%] bg-white/88 blur-[38px]" />

        {/* Very soft edge wash */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(255,255,255,0.98)_0%,rgba(255,255,255,0.96)_42%,rgba(255,255,255,0.58)_68%,rgba(255,255,255,0)_100%)]" />
      </div>

      {/* ========================================================
          PAGE
          ======================================================== */}

      <div className="relative z-10 flex h-full flex-col">

        {/* ======================================================
            HIDDEN SIDEBAR TRIGGER
            ====================================================== */}

        <header className="absolute left-4 right-4 top-4 z-30 flex items-center justify-between gap-3 sm:left-7 sm:right-7 sm:top-5">
          <motion.button
            type="button"
            onClick={() => setMobileMenuOpen(true)}
            whileHover={{ scale: 1.04 }}
            whileTap={{ scale: 0.92 }}
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-blue-100 bg-white/85 text-[#192837] shadow-[0_8px_28px_rgba(15,76,160,0.10)] backdrop-blur-xl transition-all hover:border-blue-200 hover:text-[#0B5ED7]"
            aria-label="Open navigation sidebar"
          >
            <Menu className="h-5 w-5" />
          </motion.button>

          <div className="flex items-center gap-2 rounded-[20px] border border-blue-100/80 bg-white/88 p-2 shadow-[0_12px_34px_rgba(15,76,160,0.12)] backdrop-blur-xl">
            <button
              type="button"
              onClick={() => window.open(RESOURCE_LINKS.demoVideo, '_blank', 'noopener,noreferrer')}
              className="inline-flex h-10 items-center gap-2 rounded-xl bg-[#0B5ED7] px-3.5 text-[10px] font-extrabold text-white shadow-[0_6px_18px_rgba(11,94,215,0.22)] transition-all hover:-translate-y-0.5 hover:bg-[#084FB8] sm:px-5 sm:text-xs"
            >
              <PlayCircle className="h-4 w-4" />
              <span>Demo Video</span>
            </button>

            <button
              type="button"
              onClick={() => navigate('/documentation')}
              className="inline-flex h-10 items-center gap-2 rounded-xl bg-[#061A3A] px-3.5 text-[10px] font-extrabold text-white shadow-[0_6px_18px_rgba(6,26,58,0.20)] transition-all hover:-translate-y-0.5 hover:bg-[#0B4EA2] sm:px-5 sm:text-xs"
            >
              <FileText className="h-4 w-4" />
              <span>Documentation</span>
            </button>
          </div>
        </header>

        {/* ======================================================
            HIDDEN SIDEBAR
            ====================================================== */}

        <AnimatePresence>
          {mobileMenuOpen && (
            <>
              <motion.button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                className="fixed inset-0 z-40 bg-[#192837]/20 backdrop-blur-[3px]"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                aria-label="Close navigation sidebar"
              />

              <motion.aside
                className="fixed left-0 top-0 z-50 h-[100dvh] w-[min(86vw,300px)] border-r border-[#0B5ED7]/10 bg-white/95 shadow-[12px_0_48px_rgba(25,40,55,0.14)] backdrop-blur-2xl"
                initial={{ x: '-100%' }}
                animate={{ x: 0 }}
                exit={{ x: '-100%' }}
                transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
              >
                <div className="flex h-full flex-col">
                  <div className="flex items-center justify-between px-5 py-5">
                    <div className="relative flex h-[66px] w-[175px] items-center overflow-visible">
                      <video
                        autoPlay
                        muted
                        loop
                        playsInline
                        src="/mailrakhwala-logo.mp4"
                        className="absolute left-0 top-1/2 h-[92px] w-[180px] -translate-y-1/2 scale-[1.1] object-contain object-left"
                        aria-label="MailRakhwala"
                      />
                    </div>

                    <motion.button
                      type="button"
                      onClick={() => setMobileMenuOpen(false)}
                      whileTap={{ scale: 0.9 }}
                      className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#0B5ED7]/7 text-[#192837] transition-colors hover:bg-[#0B5ED7]/12 hover:text-[#0B5ED7]"
                      aria-label="Close navigation sidebar"
                    >
                      <X className="h-5 w-5" />
                    </motion.button>
                  </div>

                  <div className="mx-5 h-px bg-[#0B5ED7]/10" />

                  <nav className="flex flex-col gap-1.5 px-4 py-6">
                    {[
                      { label: 'Home', href: '/', icon: HomeIcon },
                      { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
                      { label: 'Stream Analysis', href: '/analysis', icon: Network },
                      { label: 'Findings & CVEs', href: '/findings', icon: FindingsIcon },
                      { label: 'Forensic Reports', href: '/reports', icon: ReportsIcon },
                      { label: 'Documentation', href: '/documentation', icon: BookOpen },
                    ].map((item, index) => {
                      const Icon = item.icon;
                      const isActive =
                        item.href === '/'
                          ? window.location.pathname === '/'
                          : window.location.pathname.startsWith(item.href);

                      return (
                        <motion.button
                          key={item.href}
                          type="button"
                          custom={index}
                          variants={menuItem}
                          initial="hidden"
                          animate="visible"
                          onClick={() => {
                            setMobileMenuOpen(false);
                            navigate(item.href);
                          }}
                          className={`group flex w-full items-center gap-3 rounded-xl px-4 py-3 text-left text-sm font-semibold transition-all ${
                            isActive
                              ? 'bg-[#0B5ED7]/10 text-[#0B5ED7] shadow-sm'
                              : 'text-[#192837]/70 hover:bg-[#0B5ED7]/5 hover:text-[#0B5ED7]'
                          }`}
                        >
                          <span
                            className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition-colors ${
                              isActive
                                ? 'bg-[#0B5ED7]/10 text-[#0B5ED7]'
                                : 'bg-slate-50 text-slate-500 group-hover:bg-blue-50 group-hover:text-[#0B5ED7]'
                            }`}
                          >
                            <Icon className="h-4 w-4" />
                          </span>
                          <span>{item.label}</span>
                        </motion.button>
                      );
                    })}
                  </nav>

                  <div className="mt-auto px-5 pb-6">
                    <div className="rounded-2xl border border-[#0B5ED7]/10 bg-[#0B5ED7]/5 px-4 py-3">
                      <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#0B5ED7]">
                        MailRakhwala
                      </p>
                      <p className="mt-1 text-[11px] leading-relaxed text-[#192837]/50">
                        Email security intelligence for captured traffic.
                      </p>
                    </div>
                  </div>
                </div>
              </motion.aside>
            </>
          )}
        </AnimatePresence>

        {/* ======================================================
            HERO
            ====================================================== */}

        <main className="flex min-h-0 flex-1 items-start justify-center overflow-hidden px-5 pb-3 pt-12 sm:px-8 sm:pb-4 sm:pt-14">

          <div className="w-full max-w-[860px]">

            {/* ==================================================
                HERO LOGO
                ================================================== */}

            <motion.div
              initial={{ opacity: 0, scale: 0.88, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
              className="relative mx-auto mb-0 flex h-[195px] w-[540px] items-center justify-center sm:h-[220px] sm:w-[660px]"
            >
              <motion.div
                animate={{
                  scale: [1, 1.025, 1],
                  opacity: [0.96, 1, 0.96],
                }}
                transition={{
                  duration: 4.5,
                  repeat: Infinity,
                  ease: 'easeInOut',
                }}
                className="relative z-10 h-full w-full"
              >
                <video
                  autoPlay
                  muted
                  loop
                  playsInline
                  src="/mailrakhwala-logo.mp4"
                  className="h-full w-full object-contain mix-blend-multiply"
                  aria-label="MailRakhwala"
                />
              </motion.div>
            </motion.div>

            {/* ==================================================
                LABEL
                ================================================== */}

            <motion.div
              custom={0}
              variants={fadeUp}
              initial="hidden"
              animate="visible"
              className="flex justify-center"
            >
              <div className="inline-flex items-center gap-2 rounded-full border border-[#0B5ED7]/15 bg-white/65 px-4 py-1.5 text-[10px] font-bold tracking-[0.14em] text-[#0B5ED7] shadow-sm backdrop-blur-md sm:text-[11px]">

                <span className="h-1.5 w-1.5 rounded-full bg-[#0B5ED7]" />

                PCAP EMAIL SECURITY ANALYSIS

              </div>
            </motion.div>

            {/* ==================================================
                HEADLINE
                ================================================== */}

            <motion.h1
              custom={1}
              variants={fadeUp}
              initial="hidden"
              animate="visible"
              className="mx-auto mt-3 max-w-[860px] text-center font-[var(--font-heading)] text-[clamp(1.9rem,4.2vw,3.55rem)] font-bold leading-[0.98] tracking-[-0.045em] text-[#192837]"
            >
              Turn Captured <span className="text-[#0B5ED7]">Email Traffic</span>
              <br />
              Into Security Intelligence.
            </motion.h1>

            {/* ==================================================
                DESCRIPTION
                ================================================== */}

            <motion.p
              custom={2}
              variants={fadeUp}
              initial="hidden"
              animate="visible"
              className="mx-auto mt-2.5 max-w-[680px] text-center text-[clamp(0.78rem,1.35vw,0.92rem)] leading-[1.45] text-[#192837]/60"
            >
              Upload a PCAP or PCAPNG capture to reconstruct email traffic, assess TLS
              and cryptographic security, surface evidence-backed findings, and
              generate a clear security posture and forensic report.
            </motion.p>

            {/* ==================================================
                UPLOAD AREA
                ================================================== */}

            <motion.div
              custom={3}
              variants={fadeUp}
              initial="hidden"
              animate="visible"
              className="mx-auto mt-4 w-full max-w-[610px]"
            >

              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng"
                onChange={handleFileChange}
                className="hidden"
              />

              {/* =================================================
                  INITIAL UPLOAD CARD
                  ================================================= */}

              {!uploadResult && (
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  className={`rounded-[24px] border bg-white/78 p-2 shadow-[0_18px_55px_rgba(15,76,160,0.10)] backdrop-blur-xl transition-all duration-300 ${
                    dragActive
                      ? 'border-[#0B5ED7] shadow-[0_18px_60px_rgba(11,94,215,0.18)]'
                      : 'border-white/90'
                  }`}
                >

                  <div className="rounded-[20px] border border-dashed border-[#0B5ED7]/20 px-5 py-4 sm:px-7 sm:py-5">

                    <div className="flex flex-col items-center justify-center">

                      {/* Upload icon */}
                      <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-50 text-[#0B5ED7] shadow-sm">

                        {dragActive ? (
                          <Upload className="h-5 w-5" />
                        ) : (
                          <FileUp className="h-5 w-5" />
                        )}

                      </div>

                      <h2 className="mt-2.5 text-base font-bold tracking-tight text-[#192837] sm:text-lg">
                        Analyze an Email Capture
                      </h2>

                      <p className="mt-1 max-w-[500px] text-center text-xs text-[#192837]/50 sm:text-[13px]">
                        Upload a PCAP to inspect protocols, TLS security, findings, and posture.
                      </p>

                      {/* =================================================
                          BUTTONS

                          Selected:
                          [ START ANALYSIS ] [ CHANGE PCAP ]

                          Not selected:
                          [ CHOOSE PCAP ]
                          ================================================= */}

                      <div className="mt-2.5 flex flex-col gap-2 sm:flex-row">

                        {/* START ANALYSIS — LEFT / PURPLE */}
                        {file && (
                          <motion.button
                            type="button"
                            onClick={handleUpload}
                            disabled={uploading}
                            whileHover={!uploading ? { scale: 1.025 } : {}}
                            whileTap={!uploading ? { scale: 0.97 } : {}}
                            className="order-1 inline-flex min-w-[215px] items-center justify-center gap-2 rounded-full bg-gradient-to-r from-[#2F80ED] to-[#22B8CF] px-7 py-3.5 text-sm font-extrabold text-white shadow-[0_8px_24px_rgba(47,128,237,0.22)] ring-1 ring-white/45 transition-all hover:-translate-y-0.5 hover:brightness-[1.04] hover:saturate-[1.08] disabled:cursor-not-allowed disabled:opacity-60"
                          >
                            {uploading ? (
                              <RefreshCw className="h-4 w-4 animate-spin" />
                            ) : (
                              <Upload className="h-4 w-4" />
                            )}

                            {uploading
                              ? 'Uploading...'
                              : 'Start Analysis'}
                          </motion.button>
                        )}

                        {/* CHANGE / CHOOSE PCAP — RIGHT / WHITE */}
                        <motion.button
                          type="button"
                          onClick={() => fileInputRef.current?.click()}
                          whileHover={{ scale: 1.025 }}
                          whileTap={{ scale: 0.97 }}
                          className={`inline-flex min-w-[215px] items-center justify-center gap-2 rounded-full bg-gradient-to-r from-[#2F80ED] to-[#22B8CF] px-7 py-3.5 text-sm font-extrabold text-white shadow-[0_8px_24px_rgba(47,128,237,0.20)] ring-1 ring-white/45 transition-all hover:-translate-y-0.5 hover:brightness-[1.04] hover:saturate-[1.08] ${
                            file ? 'order-2' : 'order-1'
                          }`}
                        >
                          <FileUp className="h-4 w-4" />

                          {file ? 'Change PCAP' : 'Choose PCAP'}

                        </motion.button>

                      </div>

                      <div className="mt-3.5 flex w-full items-center justify-center">
                        <div className="h-px w-20 bg-blue-100" />
                        <span className="px-3 text-[9px] font-bold uppercase tracking-[0.14em] text-slate-400">
                          or
                        </span>
                        <div className="h-px w-20 bg-blue-100" />
                      </div>

                      <motion.button
                        type="button"
                        onClick={handleDemoPcap}
                        disabled={uploading}
                        whileHover={!uploading ? { y: -1 } : {}}
                        whileTap={!uploading ? { scale: 0.98 } : {}}
                        className="mt-2.5 inline-flex min-w-[215px] items-center justify-center gap-2 rounded-full bg-gradient-to-r from-[#2F80ED] to-[#22B8CF] px-7 py-3.5 text-sm font-extrabold text-white shadow-[0_8px_24px_rgba(47,128,237,0.22)] ring-1 ring-white/45 transition-all hover:-translate-y-0.5 hover:brightness-[1.04] hover:saturate-[1.08] disabled:cursor-not-allowed disabled:opacity-60 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        <Database className="h-3.5 w-3.5" />
                        Try Demo PCAP
                      </motion.button>

                      <p className="mt-1.5 text-center text-[8px] text-slate-400">
                        Run the prepared capture through the same real analysis flow.
                      </p>

                      <p className="mt-3 text-[9px] font-semibold tracking-[0.12em] text-[#192837]/35">
                        PCAP · PCAPNG
                      </p>

                    </div>

                  </div>

                </div>
              )}

              {/* ==================================================
                  SELECTED FILE
                  ================================================== */}

              {file && !uploadResult && (
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mt-2.5 flex items-center justify-between rounded-xl border border-[#0B5ED7]/10 bg-white/75 px-3.5 py-2.5 shadow-sm backdrop-blur-md"
                >

                  <div className="flex min-w-0 items-center gap-2.5">

                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[#0B5ED7]/10">
                      <FileUp className="h-3.5 w-3.5 text-[#0B5ED7]" />
                    </div>

                    <div className="min-w-0">

                      <p className="truncate text-xs font-semibold text-[#192837]">
                        {file.name}
                      </p>

                      <p className="text-[10px] text-[#192837]/40">
                        {formatFileSize(file.size)}
                      </p>

                    </div>

                  </div>

                  <button
                    type="button"
                    onClick={handleReset}
                    className="rounded-full p-1.5 text-[#192837]/40 transition-colors hover:bg-black/5 hover:text-[#192837]"
                    aria-label="Remove selected file"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>

                </motion.div>
              )}

              {/* ==================================================
                  ERROR
                  ================================================== */}

              {errorMessage && (
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mt-2.5 flex items-center gap-2 rounded-xl border border-red-200 bg-red-50/90 px-3.5 py-2.5 text-xs text-red-700"
                >
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  {errorMessage}
                </motion.div>
              )}

              {/* ==================================================
                  PROCESSING / RESULT
                  ================================================== */}

              {uploadResult && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="rounded-[22px] border border-white bg-white/80 p-4 shadow-[0_18px_55px_rgba(15,76,160,0.10)] backdrop-blur-xl"
                >

                  <div className="flex items-center gap-3">

                    <div
                      className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${
                        jobStatus === 'completed'
                          ? 'bg-emerald-50 text-emerald-600'
                          : jobStatus === 'failed'
                            ? 'bg-red-50 text-red-600'
                            : 'bg-[#0B5ED7]/10 text-[#0B5ED7]'
                      }`}
                    >

                      {jobStatus === 'completed' ? (
                        <CheckCircle2 className="h-5 w-5" />
                      ) : jobStatus === 'failed' ? (
                        <AlertTriangle className="h-5 w-5" />
                      ) : (
                        <RefreshCw className="h-5 w-5 animate-spin" />
                      )}

                    </div>

                    <div className="min-w-0 flex-1">

                      <p className="text-sm font-semibold text-[#192837]">
                        {jobStatus === 'completed'
                          ? 'Analysis complete'
                          : jobStatus === 'failed'
                            ? 'Analysis failed'
                            : 'Analysis in progress'}
                      </p>

                      <p className="truncate text-[10px] text-[#192837]/45">
                        {file?.name}
                      </p>

                    </div>

                    <span className="rounded-full bg-[#0B5ED7]/10 px-2.5 py-1 text-[9px] font-bold uppercase tracking-wider text-[#0B5ED7]">
                      {jobStatus || uploadResult.status}
                    </span>

                  </div>

                  {/* Processing */}
                  {isProcessing && (
                    <div className="mt-3 rounded-xl bg-[#0B5ED7]/5 px-3.5 py-3">

                      <div className="flex items-center gap-2 text-xs text-[#192837]/60">

                        <RefreshCw className="h-3.5 w-3.5 animate-spin text-[#0B5ED7]" />

                        Processing the capture...

                      </div>

                      <div className="mt-2 h-1 overflow-hidden rounded-full bg-[#0B5ED7]/10">

                        <motion.div
                          className="h-full w-1/3 rounded-full bg-[#0B5ED7]"
                          animate={{
                            x: ['0%', '210%', '0%'],
                          }}
                          transition={{
                            duration: 2,
                            repeat: Infinity,
                            ease: 'easeInOut',
                          }}
                        />

                      </div>

                    </div>
                  )}

                  {/* Completed */}
                  {jobStatus === 'completed' && (
                    <button
                      type="button"
                      onClick={() => navigate('/dashboard')}
                      className="mt-3 flex w-full items-center justify-between rounded-xl bg-[#0B5ED7] px-4 py-3 text-left text-white shadow-[0_5px_20px_rgba(11,94,215,0.20)] transition-all hover:brightness-110"
                    >

                      <div>

                        <p className="text-sm font-semibold">
                          View Security Dashboard
                        </p>

                        <p className="mt-0.5 text-[10px] text-white/65">
                          Explore the analysis results
                        </p>

                      </div>

                      <ArrowRight className="h-4 w-4" />

                    </button>
                  )}

                  {/* Failed */}
                  {jobStatus === 'failed' && (
                    <button
                      type="button"
                      onClick={handleReset}
                      className="mt-3 w-full rounded-xl border border-black/10 bg-white px-4 py-2.5 text-xs font-semibold text-[#192837] transition-colors hover:bg-black/5"
                    >
                      Try Another Capture
                    </button>
                  )}

                </motion.div>
              )}

            </motion.div>

          </div>

        </main>

      </div>
    </div>
  );
}