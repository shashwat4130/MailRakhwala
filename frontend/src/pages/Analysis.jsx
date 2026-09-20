import React, { useEffect, useState } from 'react';
import { Activity, ShieldAlert, RefreshCw, Layers, CheckCircle2, Info } from 'lucide-react';
import { getActiveAnalysisId, getAnalysisReport } from '../services/api';

export default function Analysis() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [analysisId, setAnalysisId] = useState(getActiveAnalysisId());

  useEffect(() => {
    const handleIdChange = () => setAnalysisId(getActiveAnalysisId());
    window.addEventListener('analysisIdChanged', handleIdChange);
    return () => window.removeEventListener('analysisIdChanged', handleIdChange);
  }, []);

  useEffect(() => {
    if (!analysisId) {
      setLoading(false);
      return;
    }

    setLoading(true);
    getAnalysisReport(analysisId)
      .then((data) => {
        setReport(data);
        setError(null);
      })
      .catch((err) => {
        console.error('Failed to load stream analysis:', err);
        setError(err.response?.data?.detail || 'Analysis report is not ready or failed to load.');
      })
      .finally(() => setLoading(false));
  }, [analysisId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400 gap-2">
        <RefreshCw className="w-5 h-5 animate-spin text-emerald-400" />
        <span>Loading stream reassembly and packet traces...</span>
      </div>
    );
  }

  if (!analysisId) {
    return (
      <div className="p-8 border border-gray-800 rounded-xl bg-gray-900/40 text-center space-y-3">
        <ShieldAlert className="w-10 h-10 text-amber-400 mx-auto" />
        <h3 className="text-lg font-bold text-white">No Analysis Session Selected</h3>
        <p className="text-sm text-gray-400 max-w-md mx-auto">
          Please upload or select a capture file in the Capture Ingestion view to analyze TCP/TLS streams.
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-8 border border-red-900/40 rounded-xl bg-red-950/20 text-center space-y-3">
        <ShieldAlert className="w-10 h-10 text-red-400 mx-auto" />
        <h3 className="text-lg font-bold text-white">Unable to Load Stream Analysis</h3>
        <p className="text-sm text-gray-400 max-w-md mx-auto">{error}</p>
      </div>
    );
  }

  const totalStreams = report?.session?.total_streams ?? 0;
  const protocol = report?.protocol_summary?.detected_protocol || 'Non-Email / Raw TCP';
  const hasEncryptedTraffic = totalStreams > 0 && report?.protocol_summary?.has_tls;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Stream & Flow Analysis</h1>
        <p className="text-sm text-gray-400 mt-1">
          Cryptographic inspection of reassembled sessions for capture{' '}
          <span className="font-mono text-emerald-400">{report?.session?.filename || analysisId}</span>
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="border border-gray-800 bg-gray-900/40 p-5 rounded-xl">
          <span className="text-xs font-mono uppercase text-gray-400">Total Streams</span>
          <div className="mt-2 text-3xl font-bold font-mono text-white">{totalStreams}</div>
          <p className="text-xs text-gray-500 mt-1 font-mono">Reassembled TCP conversations</p>
        </div>
        <div className="border border-gray-800 bg-gray-900/40 p-5 rounded-xl">
          <span className="text-xs font-mono uppercase text-gray-400">Primary Protocol</span>
          <div className="mt-2 text-2xl font-bold font-mono text-blue-400">{protocol}</div>
          <p className="text-xs text-gray-500 mt-1 font-mono">Dissected layer protocol</p>
        </div>
        <div className="border border-gray-800 bg-gray-900/40 p-5 rounded-xl">
          <span className="text-xs font-mono uppercase text-gray-400">Capture File Size</span>
          <div className="mt-2 text-2xl font-bold font-mono text-gray-300">
            {((report?.session?.filesize_bytes || 0) / 1024).toFixed(1)} KB
          </div>
          <p className="text-xs text-gray-500 mt-1 font-mono">Forensic payload inspected</p>
        </div>
      </div>

      {!hasEncryptedTraffic ? (
        <div className="border border-gray-800 bg-gray-900/30 rounded-xl p-8 text-center space-y-3">
          <Info className="w-8 h-8 text-blue-400 mx-auto" />
          <h3 className="text-base font-semibold text-white">No Encrypted TLS/Email Streams Detected</h3>
          <p className="text-sm text-gray-400 max-w-xl mx-auto">
            The analyzed capture contains unencrypted traffic (e.g., standard FTP, plaintext communications) with no
            TLS handshakes, STARTTLS negotiations, or cryptographic stream evidence.
          </p>
        </div>
      ) : (
        <div className="border border-gray-800 bg-gray-900/40 rounded-xl p-6 space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-emerald-400" />
            Active Cryptographic Streams
          </h3>
          <div className="font-mono text-xs text-gray-400">
            Session ID: {report?.session?.session_id} — Total evaluated streams: {totalStreams}
          </div>
        </div>
      )}
    </div>
  );
}