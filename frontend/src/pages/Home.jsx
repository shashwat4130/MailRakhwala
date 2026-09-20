import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileUp, RefreshCw, AlertTriangle, ArrowRight } from 'lucide-react';
import { uploadCapture, getAnalysisJob, setActiveAnalysisId } from '../services/api';

export default function Home() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [jobStatus, setJobStatus] = useState(null);
  const fileInputRef = useRef(null);

  useEffect(() => {
    if (!uploadResult?.analysis_id || jobStatus === 'completed' || jobStatus === 'failed') {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const job = await getAnalysisJob(uploadResult.analysis_id);
        setJobStatus(job.status);
        if (job.status === 'completed') {
          setActiveAnalysisId(uploadResult.analysis_id);
          clearInterval(interval);
        } else if (job.status === 'failed') {
          clearInterval(interval);
        }
      } catch (err) {
        console.error("Status check failed:", err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [uploadResult, jobStatus]);

  const handleFileChange = (e) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      const ext = selectedFile.name.toLowerCase();
      if (!ext.endsWith('.pcap') && !ext.endsWith('.pcapng')) {
        setErrorMessage('Only .pcap and .pcapng files are supported.');
        setFile(null);
        return;
      }
      setFile(selectedFile);
      setErrorMessage(null);
      setUploadResult(null);
      setJobStatus(null);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setErrorMessage(null);

    try {
      const result = await uploadCapture(file);
      setUploadResult(result);
      setJobStatus(result.status || 'queued');
      setActiveAnalysisId(result.analysis_id);
    } catch (err) {
      const msg = err.response?.data?.detail || 'Failed to upload and enqueue capture.';
      setErrorMessage(msg);
    } finally {
      setUploading(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setUploadResult(null);
    setErrorMessage(null);
    setJobStatus(null);
    setActiveAnalysisId(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="space-y-6">
      <div className="border border-gray-800 bg-gray-900/50 rounded-xl p-8 backdrop-blur-sm relative overflow-hidden">
        <div className="max-w-2xl mx-auto text-center space-y-4">
          <h2 className="text-xl font-bold text-white tracking-tight">Capture File Ingestion</h2>
          <p className="text-sm text-gray-400">
            Passive, zero-decryption cryptographic inspection for email communications.
          </p>

          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".pcap,.pcapng"
            className="hidden"
          />

          <div className="pt-4 flex items-center justify-center gap-3">
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="px-5 py-2.5 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors cursor-pointer inline-flex items-center gap-2 shadow-sm"
            >
              <FileUp className="w-4 h-4" />
              {file ? 'Change Capture File' : 'Browse PCAP / PCAPNG'}
            </button>

            {file && (
              <button
                type="button"
                onClick={handleUpload}
                disabled={uploading}
                className="px-5 py-2.5 text-sm font-medium rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-800 disabled:text-gray-500 text-white transition-colors cursor-pointer inline-flex items-center gap-2 shadow-sm"
              >
                {uploading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                {uploading ? 'Ingesting...' : 'Upload & Enqueue'}
              </button>
            )}

            {(file || uploadResult || errorMessage) && (
              <button
                type="button"
                onClick={handleReset}
                disabled={uploading}
                className="px-4 py-2.5 text-sm font-medium rounded-lg bg-gray-800 text-gray-300 hover:text-white hover:bg-gray-700 transition-colors"
              >
                Reset
              </button>
            )}
          </div>

          {file && (
            <div className="text-xs font-mono text-gray-400 pt-1">
              Selected: <span className="text-blue-400 font-semibold">{file.name}</span> ({(file.size / 1024).toFixed(1)} KB)
            </div>
          )}

          {errorMessage && (
            <div className="mt-4 p-4 rounded-lg bg-red-950/40 border border-red-800/60 text-red-300 text-sm flex items-center justify-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {uploadResult && (
            <div className="mt-6 p-5 rounded-xl bg-gray-950 border border-gray-800 text-left space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-gray-800 pb-2">
                <span className="text-gray-400">Analysis ID:</span>
                <span className="text-emerald-400 font-semibold">{uploadResult.analysis_id}</span>
              </div>
              <div className="flex items-center justify-between border-b border-gray-800 pb-2">
                <span className="text-gray-400">Status:</span>
                <span className={`px-2 py-0.5 rounded font-bold uppercase ${
                  jobStatus === 'completed'
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                    : jobStatus === 'failed'
                    ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                    : 'bg-amber-500/10 text-amber-400 border border-amber-500/30 animate-pulse'
                }`}>
                  {jobStatus || uploadResult.status}
                </span>
              </div>

              {jobStatus === 'completed' ? (
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={() => navigate('/dashboard')}
                    className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-sans text-sm font-semibold rounded-lg flex items-center justify-center gap-2 transition-colors cursor-pointer shadow-lg shadow-emerald-950/50"
                  >
                    Analysis Complete — View Dashboard
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              ) : (
                <div className="text-gray-400 flex items-center gap-2 pt-1 font-sans">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" />
                  Processing cryptographic streams and posture metrics...
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}