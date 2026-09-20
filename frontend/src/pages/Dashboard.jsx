import React, { useEffect, useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Activity, 
  FileText, 
  Layers, 
  AlertTriangle, 
  RefreshCw, 
  Info, 
  CheckCircle2,
  MailQuestion
} from 'lucide-react';
import { getActiveAnalysisId, getAnalysisReport } from '../services/api';

export default function Dashboard() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

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
        console.error('Failed to load dashboard report:', err);
        setError(err.response?.data?.detail || 'Analysis report could not be retrieved.');
      })
      .finally(() => setLoading(false));
  }, [analysisId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400 gap-2 font-mono text-sm">
        <RefreshCw className="w-5 h-5 animate-spin text-emerald-400" />
        <span>Aggregating posture scoring and telemetry...</span>
      </div>
    );
  }

  const effectiveId = analysisId || resolveCurrentId();

  if (!effectiveId) {
    return (
      <div className="p-10 border border-gray-800 rounded-xl bg-gray-900/40 text-center space-y-3">
        <ShieldAlert className="w-12 h-12 text-amber-400 mx-auto" />
        <h3 className="text-lg font-bold text-white">No Forensic Session Active</h3>
        <p className="text-sm text-gray-400 max-w-md mx-auto">
          Please upload a capture file via Capture Ingestion to view cryptographic posture assessments.
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-10 border border-red-900/40 rounded-xl bg-red-950/20 text-center space-y-3">
        <AlertTriangle className="w-12 h-12 text-red-400 mx-auto" />
        <h3 className="text-lg font-bold text-white">Dashboard Telemetry Error</h3>
        <p className="text-sm text-gray-400 max-w-md mx-auto">{error}</p>
      </div>
    );
  }

  // Derive Email & Cryptographic Signal Status
  const totalStreams = report?.session?.total_streams ?? 0;
  const findings = report?.compliance_findings || [];
  const postureScore = report?.posture_report?.posture_score ?? 100;
  const postureSeverity = report?.posture_report?.severity || 'LOW';
  const riskClass = report?.risk_classification?.risk_class || 'LOW';
  const detectedProtocol = report?.protocol_summary?.detected_protocol || 'Non-Email';
  const hasEmailSignals = Boolean(
    report?.protocol_summary?.has_tls || 
    (totalStreams > 0 && ['SMTP', 'SMTPS', 'IMAP', 'IMAPS', 'POP3', 'POP3S', 'TLS'].includes(detectedProtocol.toUpperCase()))
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Security Posture Dashboard</h1>
        <p className="text-sm text-gray-400 mt-1">
          Forensic cryptographic assessment for session <span className="font-mono text-emerald-400">{effectiveId}</span>
        </p>
      </div>

      {/* Clear Plain English Banner for Non-Email / Plaintext Traffic */}
      {!hasEmailSignals && (
        <div className="border border-blue-500/30 bg-blue-950/20 rounded-xl p-5 flex items-start gap-4">
          <div className="p-2.5 bg-blue-500/10 border border-blue-500/20 rounded-lg text-blue-400 shrink-0">
            <MailQuestion className="w-6 h-6" />
          </div>
          <div className="space-y-1">
            <h4 className="text-sm font-bold text-blue-300">No Email or TLS Signals Detected</h4>
            <p className="text-xs text-gray-300 leading-relaxed">
              This capture contains unencrypted traffic (such as standard FTP or plaintext transport) without any 
              STARTTLS handshakes, SMTPS, IMAPS, or X.509 certificates. 
              The <span className="font-mono text-emerald-400 font-semibold">100 / 100</span> rating reflects that 
              zero cryptographic vulnerabilities or deprecated ciphers were flagged, because no TLS protocol negotiation occurred.
            </p>
          </div>
        </div>
      )}

      {/* Top 4 KPI Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="border border-gray-800 bg-gray-900/40 p-5 rounded-xl">
          <div className="flex items-center justify-between text-xs font-mono uppercase text-gray-400">
            <span>Cryptographic Score</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-3xl font-bold font-mono text-emerald-400">
            {postureScore} <span className="text-sm text-gray-500 font-normal">/ 100</span>
          </div>
          <p className="text-xs text-gray-500 mt-1 font-mono uppercase">
            Posture: <span className="text-emerald-400 font-bold">{postureSeverity}</span>
          </p>
        </div>

        <div className="border border-gray-800 bg-gray-900/40 p-5 rounded-xl">
          <div className="flex items-center justify-between text-xs font-mono uppercase text-gray-400">
            <span>Email / TLS Streams</span>
            <Layers className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-2 text-3xl font-bold font-mono text-white">
            {hasEmailSignals ? totalStreams : 0}
          </div>
          <p className="text-xs text-gray-500 mt-1 font-mono">
            {hasEmailSignals ? 'Encrypted email sessions' : '0 detected in capture'}
          </p>
        </div>

        <div className="border border-gray-800 bg-gray-900/40 p-5 rounded-xl">
          <div className="flex items-center justify-between text-xs font-mono uppercase text-gray-400">
            <span>Identified Findings</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-3xl font-bold font-mono text-amber-400">
            {findings.length}
          </div>
          <p className="text-xs text-gray-500 mt-1 font-mono">
            {findings.length === 0 ? 'Zero cipher / compliance flaws' : 'Weaknesses identified'}
          </p>
        </div>

        <div className="border border-gray-800 bg-gray-900/40 p-5 rounded-xl">
          <div className="flex items-center justify-between text-xs font-mono uppercase text-gray-400">
            <span>ML Risk Class</span>
            <Activity className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2 text-3xl font-bold font-mono text-purple-400 uppercase">
            {riskClass}
          </div>
          <p className="text-xs text-gray-500 mt-1 font-mono">AI Model Classification</p>
        </div>
      </div>

      {/* Forensic Inspection Summary Box */}
      <div className="border border-gray-800 bg-gray-900/40 rounded-xl p-6 space-y-4">
        <h3 className="text-base font-semibold text-white">Capture Inspection Summary</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-4 bg-gray-950 rounded-lg border border-gray-800">
            <span className="text-gray-400 block mb-1">Target Filename</span>
            <span className="text-white text-sm font-semibold truncate block">
              {report?.session?.filename || 'capture.pcap'}
            </span>
          </div>

          <div className="p-4 bg-gray-950 rounded-lg border border-gray-800">
            <span className="text-gray-400 block mb-1">Detected Flow Type</span>
            <span className={`text-sm font-bold block ${hasEmailSignals ? 'text-emerald-400' : 'text-blue-400'}`}>
              {hasEmailSignals ? 'Encrypted Mail (STARTTLS / TLS)' : 'Plaintext / Non-Cryptographic'}
            </span>
          </div>

          <div className="p-4 bg-gray-950 rounded-lg border border-gray-800">
            <span className="text-gray-400 block mb-1">Standards Baseline</span>
            <span className="text-gray-300 text-sm block">NIST SP 800-52r2 / RFC 8996</span>
          </div>
        </div>
      </div>
    </div>
  );
}