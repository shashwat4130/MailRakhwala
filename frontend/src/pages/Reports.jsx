import React, { useEffect, useState } from 'react';
import { FileText, Download, ShieldAlert, RefreshCw } from 'lucide-react';
import { getActiveAnalysisId, getAnalysisReport, exportReportPDFUrl } from '../services/api';

export default function Reports() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Check custom helper, with fallback to legacy keys if Dashboard used them
  const resolveCurrentId = () => {
    return (
      getActiveAnalysisId() ||
      localStorage.getItem('active_analysis_id') ||
      localStorage.getItem('analysis_id') ||
      null
    );
  };

  const [analysisId, setAnalysisId] = useState(resolveCurrentId());

  useEffect(() => {
    const handleIdChange = () => setAnalysisId(resolveCurrentId());
    window.addEventListener('analysisIdChanged', handleIdChange);
    window.addEventListener('storage', handleIdChange);
    return () => {
      window.removeEventListener('analysisIdChanged', handleIdChange);
      window.removeEventListener('storage', handleIdChange);
    };
  }, []);

  useEffect(() => {
    const currentId = resolveCurrentId();
    if (!currentId) {
      setLoading(false);
      return;
    }

    setLoading(true);
    getAnalysisReport(currentId)
      .then((data) => {
        setReport(data);
        setError(null);
      })
      .catch((err) => {
        console.error('Failed to load forensic report:', err);
        setError(err.response?.data?.detail || 'Report could not be retrieved.');
      })
      .finally(() => setLoading(false));
  }, [analysisId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400 gap-2">
        <RefreshCw className="w-5 h-5 animate-spin text-emerald-400" />
        <span>Compiling forensic audit package...</span>
      </div>
    );
  }

  const effectiveId = analysisId || resolveCurrentId();

  if (!effectiveId) {
    return (
      <div className="p-8 border border-gray-800 rounded-xl bg-gray-900/40 text-center space-y-3">
        <ShieldAlert className="w-10 h-10 text-amber-400 mx-auto" />
        <h3 className="text-lg font-bold text-white">No Forensic Report Generated</h3>
        <p className="text-sm text-gray-400 max-w-md mx-auto">
          Please upload and analyze a PCAP file in Capture Ingestion to generate executive and forensic security reports.
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-8 border border-red-900/40 rounded-xl bg-red-950/20 text-center space-y-3">
        <ShieldAlert className="w-10 h-10 text-red-400 mx-auto" />
        <h3 className="text-lg font-bold text-white">Audit Report Unavailable</h3>
        <p className="text-sm text-gray-400 max-w-md mx-auto">{error}</p>
      </div>
    );
  }

  const handleDownloadJSON = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mailrakhwala_audit_${effectiveId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Forensic Reports</h1>
          <p className="text-sm text-gray-400 mt-1">
            Audit exports and machine-readable evidence packages for session{' '}
            <span className="font-mono text-emerald-400">{effectiveId}</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleDownloadJSON}
            className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 text-sm font-medium rounded-lg inline-flex items-center gap-2 cursor-pointer transition-colors"
          >
            <Download className="w-4 h-4" />
            Export JSON
          </button>
          <a
            href={exportReportPDFUrl(effectiveId)}
            target="_blank"
            rel="noreferrer"
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg inline-flex items-center gap-2 cursor-pointer transition-colors shadow-sm"
          >
            <FileText className="w-4 h-4" />
            Download PDF Report
          </a>
        </div>
      </div>

      <div className="border border-gray-800 bg-gray-900/40 rounded-xl p-6 space-y-4">
        <h3 className="text-base font-semibold text-white">Executive Summary</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div className="p-4 bg-gray-950 rounded-lg border border-gray-800">
            <span className="text-gray-400 block mb-1">Target Filename</span>
            <span className="text-white text-sm">{report?.session?.filename || 'N/A'}</span>
          </div>
          <div className="p-4 bg-gray-950 rounded-lg border border-gray-800">
            <span className="text-gray-400 block mb-1">Analysis Status</span>
            <span className="text-emerald-400 text-sm font-bold uppercase">{report?.session?.status || 'COMPLETED'}</span>
          </div>
          <div className="p-4 bg-gray-950 rounded-lg border border-gray-800">
            <span className="text-gray-400 block mb-1">Reassembled Streams</span>
            <span className="text-white text-sm">{report?.session?.total_streams ?? 0}</span>
          </div>
          <div className="p-4 bg-gray-950 rounded-lg border border-gray-800">
            <span className="text-gray-400 block mb-1">Identified Posture Score</span>
            <span className="text-emerald-400 text-sm font-bold">
              {report?.posture_report?.posture_score ?? 100} / 100
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}