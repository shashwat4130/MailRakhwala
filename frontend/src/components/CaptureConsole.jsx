import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  UploadCloud,
  FileUp,
  Database,
  RefreshCw,
  AlertTriangle,
  FileText,
  X,
  Sparkles,
} from 'lucide-react';
import { uploadCapture, getAnalysisJob, setActiveAnalysisId } from '../services/api';
import { useAnalysisContext } from '../context/AnalysisContext';
import AnalysisProgress from './AnalysisProgress';

const DEMO_PCAP_URL = '/mailrakhwala-demo.pcap';

const CaptureConsole = React.forwardRef(function CaptureConsole(
  {
    isModal = false,
    onClose = null,
    onAnalysisStart = null,
    className = '',
  },
  ref
) {
  const navigate = useNavigate();
  const { clear: clearAnalysisState } = useAnalysisContext();

  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [jobStatus, setJobStatus] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [demoMode, setDemoMode] = useState(false);

  const fileInputRef = useRef(null);

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
        }

        if (job.status === 'failed') {
          clearInterval(interval);
          setErrorMessage(job.error || 'Analysis pipeline encountered an unrecoverable packet parse error.');
        }
      } catch (err) {
        console.error('Capture job status check failed:', err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [uploadResult, jobStatus]);

  const validateAndSelectFile = (selectedFile) => {
    if (!selectedFile) return;

    const fileName = selectedFile.name.toLowerCase();
    if (!fileName.endsWith('.pcap') && !fileName.endsWith('.pcapng')) {
      setErrorMessage('Only network packet captures (.pcap and .pcapng) are supported.');
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

  const handleUpload = async () => {
    if (!file) {
      fileInputRef.current?.click();
      return;
    }

    clearAnalysisState();
    setUploading(true);
    setErrorMessage(null);
    setDemoMode(false);
    if (onAnalysisStart) onAnalysisStart();

    try {
      const result = await uploadCapture(file);
      setUploadResult(result);
      setJobStatus(result.status || 'queued');
      setActiveAnalysisId(result.analysis_id);
    } catch (err) {
      const message =
        err.response?.data?.detail || 'Failed to ingest and enqueue packet capture.';
      setErrorMessage(message);
    } finally {
      setUploading(false);
    }
  };

  const handleDemoPcap = async () => {
    if (uploading) return;

    clearAnalysisState();
    setUploading(true);
    setErrorMessage(null);
    setUploadResult(null);
    setJobStatus(null);
    setDemoMode(true);
    if (onAnalysisStart) onAnalysisStart();

    try {
      const response = await fetch(DEMO_PCAP_URL);
      if (!response.ok) {
        throw new Error('Bundled demo capture file is currently inaccessible.');
      }

      const blob = await response.blob();
      const demoFile = new File([blob], 'mailrakhwala-demo.pcap', {
        type: 'application/vnd.tcpdump.pcap',
      });

      const result = await uploadCapture(demoFile);
      setFile(demoFile);
      setUploadResult(result);
      setJobStatus(result.status || 'queued');
      setActiveAnalysisId(result.analysis_id);
    } catch (err) {
      console.error('Demo capture initialization failed:', err);
      setErrorMessage(
        err?.message ||
          err?.response?.data?.detail ||
          'Failed to initialize bundled demo analysis.'
      );
    } finally {
      setUploading(false);
    }
  };

  const handleReset = () => {
    clearAnalysisState();
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

  const formatFileSize = (bytes) => {
    if (!bytes) return '0 KB';
    const kb = bytes / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    return `${(kb / 1024).toFixed(2)} MB`;
  };

  React.useImperativeHandle(ref, () => ({
    triggerUpload: handleUpload,
    triggerDemo: handleDemoPcap,
    openPicker: () => fileInputRef.current?.click(),
  }));

  const isAnalyzing = Boolean(uploadResult || uploading);

  const handleViewDashboard = () => {
    if (onClose) onClose();
    navigate('/dashboard');
  };

  return (
    <div className={`w-full ${className}`}>
      <input
        ref={fileInputRef}
        type="file"
        accept=".pcap,.pcapng"
        onChange={handleFileChange}
        className="hidden"
      />

      <AnimatePresence mode="wait">
        {!isAnalyzing ? (
          <motion.div
            key="capture-form"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
            className="w-full"
          >
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`relative rounded-2xl border bg-white p-4 sm:p-5 md:p-6 shadow-sm transition-all duration-200 ${
                dragActive
                  ? 'border-[#111111] ring-2 ring-[#111111]/15 bg-[#FAFAF8]'
                  : 'border-[#E5E5E0] hover:border-[#D0D0CB]'
              }`}
            >
              {isModal && onClose && (
                <button
                  type="button"
                  onClick={onClose}
                  className="absolute top-3 right-3 h-7 w-7 flex items-center justify-center rounded-lg text-neutral-400 hover:text-[#111111] hover:bg-[#F0F0EB] transition"
                  aria-label="Close capture panel"
                >
                  <X className="h-4 w-4" />
                </button>
              )}

              <div className="flex flex-col items-center text-center">
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className={`cursor-pointer mb-2 sm:mb-2.5 flex h-10 w-10 sm:h-11 sm:w-11 items-center justify-center rounded-xl bg-[#111111] text-white shadow-sm transition-all duration-200 hover:bg-[#222222] active:scale-95 ${
                    dragActive ? 'scale-105 ring-4 ring-[#111111]/10' : ''
                  }`}
                  title="Choose PCAP file"
                >
                  {dragActive ? (
                    <UploadCloud className="h-5 w-5 text-white" />
                  ) : (
                    <FileUp className="h-5 w-5 text-white" />
                  )}
                </div>

                <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-[#F7F7F5] border border-[#E5E5E0] text-[9px] sm:text-[10px] font-mono font-bold uppercase tracking-wider text-neutral-600 mb-1">
                  <Sparkles className="h-2.5 w-2.5 sm:h-3 sm:w-3 text-[#111111]" />
                  Passive PCAP / PCAPNG Ingestion
                </div>

                <h2 className="text-base sm:text-lg md:text-xl font-black tracking-tight text-[#111111]">
                  Ingest Network Packet Capture
                </h2>
                <p className="mt-1 max-w-[440px] text-[11px] sm:text-xs leading-relaxed text-[#666666]">
                  Drop a <code className="font-mono font-bold text-neutral-800 bg-[#F0F0EC] px-1 py-0.5 rounded">.pcap</code> or <code className="font-mono font-bold text-neutral-800 bg-[#F0F0EC] px-1 py-0.5 rounded">.pcapng</code> file to passively reconstruct SMTP, IMAP, and POP3 telemetry without decryption.
                </p>

                {file && (
                  <div className="mt-3 flex items-center justify-between rounded-xl border border-[#E5E5E0] bg-[#F7F7F5] px-3.5 py-2 w-full max-w-md shadow-xs">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[#111111] text-white">
                        <FileText className="h-4 w-4" />
                      </div>
                      <div className="min-w-0 text-left">
                        <p className="truncate text-xs font-bold text-[#111111]">{file.name}</p>
                        <p className="text-[10px] font-mono text-[#666666]">{formatFileSize(file.size)}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={handleReset}
                        className="p-1 rounded-md text-neutral-400 hover:text-[#111111] hover:bg-[#EAEAE8] transition"
                        aria-label="Remove selected file"
                        title="Remove file"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                )}

                <div className="mt-3.5 sm:mt-4 w-full flex flex-col items-center gap-1.5 sm:gap-2">
                  <div className="flex flex-col sm:flex-row items-center justify-center gap-2.5 sm:gap-3 w-full max-w-md">
                    <button
                      type="button"
                      onClick={handleUpload}
                      disabled={uploading}
                      className="w-full sm:w-auto sm:flex-1 min-w-[170px] inline-flex items-center justify-center gap-2 rounded-xl bg-[#111111] px-5 sm:px-6 py-2.5 sm:py-3 text-xs font-bold uppercase tracking-wider text-white shadow-xs transition-all duration-150 hover:bg-[#222222] hover:shadow-sm active:scale-[0.985] focus:outline-none focus:ring-2 focus:ring-[#111111] focus:ring-offset-2 disabled:opacity-60"
                    >
                      {uploading && !demoMode ? (
                        <RefreshCw className="h-4 w-4 animate-spin text-white" />
                      ) : (
                        <UploadCloud className="h-4 w-4 text-white" />
                      )}
                      <span>
                        {uploading && !demoMode
                          ? 'Preparing Capture...'
                          : 'Upload PCAP'}
                      </span>
                    </button>

                    <button
                      type="button"
                      onClick={handleDemoPcap}
                      disabled={uploading}
                      className="w-full sm:w-auto sm:flex-1 min-w-[170px] inline-flex items-center justify-center gap-2 rounded-xl bg-[#1A1A1A] border border-[#333333] px-5 sm:px-6 py-2.5 sm:py-3 text-xs font-bold uppercase tracking-wider text-[#F0F0EE] shadow-xs transition-all duration-150 hover:bg-[#262626] hover:text-white hover:border-[#444444] active:scale-[0.985] focus:outline-none focus:ring-2 focus:ring-[#111111] focus:ring-offset-2 disabled:opacity-60"
                    >
                      {uploading && demoMode ? (
                        <RefreshCw className="h-4 w-4 animate-spin text-white" />
                      ) : (
                        <Database className="h-4 w-4 text-neutral-300" />
                      )}
                      <span>
                        {uploading && demoMode
                          ? 'Loading Demo...'
                          : 'Try Demo PCAP'}
                      </span>
                    </button>
                  </div>

                  {!file && (
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="text-[11px] sm:text-xs font-normal text-[#666666] hover:text-[#111111] underline transition-colors cursor-pointer mt-0.5 bg-transparent border-0 p-0 shadow-none outline-none focus:ring-0"
                    >
                      Or browse local filesystem (.pcap, .pcapng)
                    </button>
                  )}
                </div>

                {errorMessage && (
                  <div className="mt-3.5 w-full max-w-md flex items-center gap-2.5 rounded-xl border border-red-200 bg-red-50 p-2.5 text-xs text-red-700 text-left">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-red-600" />
                    <span>{errorMessage}</span>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        ) : (
          <motion.div
            key="analyzing-progress"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
            className="w-full flex flex-col items-center justify-center py-2"
          >
            <AnalysisProgress
              filename={file?.name || (demoMode ? 'mailrakhwala-demo.pcap' : 'Capture packet stream')}
              isDemo={demoMode}
              status={jobStatus === 'completed' ? 'completed' : jobStatus === 'failed' ? 'failed' : 'analyzing'}
              errorMessage={errorMessage}
              onViewDashboard={handleViewDashboard}
              onRetry={handleReset}
            />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
});

export default CaptureConsole;
