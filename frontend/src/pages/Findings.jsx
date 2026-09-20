import React, { useEffect, useState } from 'react';
import { ShieldAlert, AlertTriangle, RefreshCw, CheckCircle2 } from 'lucide-react';
import { getActiveAnalysisId, getAnalysisReport } from '../services/api';

export default function Findings() {
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
        console.error('Failed to load findings:', err);
        setError(err.response?.data?.detail || 'Analysis findings not available or capture analysis incomplete.');
      })
      .finally(() => setLoading(false));
  }, [analysisId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400 gap-2">
        <RefreshCw className="w-5 h-5 animate-spin text-emerald-400" />
        <span>Evaluating compliance rules and CVE correlations...</span>
      </div>
    );
  }

  const effectiveId = analysisId || resolveCurrentId();

  if (!effectiveId) {
    return (
      <div className="p-8 border border-gray-800 rounded-xl bg-gray-900/40 text-center space-y-3">
        <ShieldAlert className="w-10 h-10 text-amber-400 mx-auto" />
        <h3 className="text-lg font-bold text-white">No Active Analysis Ingested</h3>
        <p className="text-sm text-gray-400 max-w-md mx-auto">
          Please upload a network trace to correlate cipher weaknesses and NIST compliance findings.
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-8 border border-red-900/40 rounded-xl bg-red-950/20 text-center space-y-3">
        <AlertTriangle className="w-10 h-10 text-red-400 mx-auto" />
        <h3 className="text-lg font-bold text-white">Error Retrieving Findings</h3>
        <p className="text-sm text-gray-400 max-w-md mx-auto">{error}</p>
      </div>
    );
  }

  const findings = report?.compliance_findings || [];
  const vulnerabilities = report?.vulnerability_mappings || [];
  const totalIssues = findings.length + vulnerabilities.length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Findings & Vulnerabilities</h1>
        <p className="text-sm text-gray-400 mt-1">
          Automated CVE mapping, cipher vulnerabilities, and standards non-compliance for session{' '}
          <span className="font-mono text-emerald-400">{effectiveId}</span>
        </p>
      </div>

      {totalIssues === 0 ? (
        <div className="border border-gray-800 bg-gray-900/40 rounded-xl p-10 text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-emerald-500/10 text-emerald-400 flex items-center justify-center mx-auto border border-emerald-500/20">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <div className="space-y-1">
            <h3 className="text-base font-bold text-white">Zero Cryptographic Vulnerabilities or CVEs Detected</h3>
            <p className="text-sm text-gray-400 max-w-lg mx-auto">
              No deprecated ciphers, expired certificates, or protocol downgrades were detected in this capture.
              Plaintext or non-TLS sessions do not trigger TLS compliance deductions.
            </p>
          </div>
          <div className="pt-2 text-xs font-mono text-gray-500">
            Compliance Engine: NIST SP 800-52r2 / RFC 8996 Verified
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {findings.map((f, idx) => (
            <div key={idx} className="border border-amber-900/40 bg-amber-950/10 p-5 rounded-xl space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs uppercase px-2 py-0.5 rounded bg-amber-500/20 text-amber-400">
                  {f.rule_id || 'RULE'}
                </span>
                <span className="text-xs text-gray-400">{f.stream_id}</span>
              </div>
              <p className="text-sm font-semibold text-white">{f.description}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}