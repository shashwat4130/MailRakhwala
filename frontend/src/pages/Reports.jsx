import React, { useEffect, useMemo, useState } from 'react';
import {
  FileText,
  Download,
  ShieldAlert,
  RefreshCw,
  ShieldCheck,
  Network,
  Mail,
  LockKeyhole,
  AlertTriangle,
} from 'lucide-react';
import {
  getActiveAnalysisId,
  getAnalysisReport,
  exportReportPDFUrl,
} from '../services/api';

const EMAIL_PROTOCOLS = new Set([
  'SMTP',
  'SMTPS',
  'IMAP',
  'IMAPS',
  'POP3',
  'POP3S',
]);

function normalizeProtocol(value) {
  return String(value ?? '')
    .trim()
    .toUpperCase();
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

export default function Reports() {
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
    const handleIdChange = () => {
      setAnalysisId(resolveCurrentId());
    };

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
      setReport(null);
      setError(null);
      setLoading(false);
      return;
    }

    let cancelled = false;

    setLoading(true);
    setError(null);

    getAnalysisReport(currentId)
      .then((data) => {
        if (cancelled) return;
        setReport(data);
      })
      .catch((err) => {
        if (cancelled) return;

        console.error('Failed to load forensic report:', err);

        setReport(null);
        setError(
          err?.response?.data?.detail ||
            'Report could not be retrieved.'
        );
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  const effectiveId = analysisId || resolveCurrentId();

  const reportMeta = useMemo(() => {
    const totalStreams = Number(report?.session?.total_streams ?? 0);

    const detectedProtocol = normalizeProtocol(
      report?.protocol_summary?.detected_protocol
    );

    /*
     * MailRakhwala's cryptographic assessment is applicable only
     * when the capture actually contains identifiable email traffic.
     *
     * A TCP stream by itself is NOT evidence of an email session.
     */
    const hasEmailSignals =
      totalStreams > 0 &&
      EMAIL_PROTOCOLS.has(detectedProtocol);

    const findings = Array.isArray(report?.compliance_findings)
      ? report.compliance_findings
      : [];

    const rawScore = report?.posture_report?.posture_score;

    const validScore =
      isFiniteNumber(rawScore) &&
      rawScore >= 0 &&
      rawScore <= 100;

    const postureScore =
      hasEmailSignals && validScore
        ? rawScore
        : null;

    const riskClass =
      hasEmailSignals
        ? (
            report?.risk_classification?.predicted_risk_class ||
            report?.risk_classification?.risk_class ||
            null
          )
        : null;

    const anomaly =
      hasEmailSignals &&
      typeof report?.anomaly_detection?.is_anomaly === 'boolean'
        ? report.anomaly_detection.is_anomaly
        : null;

    /*
     * For an out-of-scope capture, the report must not present
     * compliance findings as an assessed email-security result.
     */
    const assessedFindings = hasEmailSignals
      ? findings
      : [];

    return {
      totalStreams,
      detectedProtocol,
      hasEmailSignals,
      postureScore,
      riskClass,
      anomaly,
      findings: assessedFindings,
      rawFindingCount: findings.length,
    };
  }, [report]);

  if (loading) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center p-8">
        <div className="flex items-center gap-3 text-slate-500">
          <RefreshCw className="w-5 h-5 animate-spin text-[#0B5ED7]" />
          <span className="text-sm font-medium">
            Compiling forensic audit package...
          </span>
        </div>
      </div>
    );
  }

  if (!effectiveId) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center p-8">
        <div className="w-full max-w-lg rounded-3xl border border-blue-100 bg-white p-10 text-center shadow-[0_18px_55px_rgba(15,76,160,0.08)]">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-amber-50 text-amber-500">
            <ShieldAlert className="w-7 h-7" />
          </div>

          <h3 className="mt-5 text-xl font-black text-slate-900">
            No Forensic Report Generated
          </h3>

          <p className="mx-auto mt-3 max-w-md text-sm leading-6 text-slate-500">
            Please upload and analyze a PCAP file in Capture Ingestion
            to generate an executive and forensic security report.
          </p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center p-8">
        <div className="w-full max-w-lg rounded-3xl border border-red-100 bg-white p-10 text-center shadow-xl shadow-red-100/30">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-red-50 text-red-500">
            <ShieldAlert className="w-7 h-7" />
          </div>

          <h3 className="mt-5 text-xl font-black text-slate-900">
            Audit Report Unavailable
          </h3>

          <p className="mx-auto mt-3 max-w-md text-sm leading-6 text-slate-500">
            {error}
          </p>
        </div>
      </div>
    );
  }

  const {
    totalStreams,
    detectedProtocol,
    hasEmailSignals,
    postureScore,
    riskClass,
    anomaly,
    findings,
  } = reportMeta;

  const handleDownloadJSON = () => {
    const blob = new Blob(
      [JSON.stringify(report, null, 2)],
      { type: 'application/json' }
    );

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');

    anchor.href = url;
    anchor.download = `mailrakhwala_audit_${effectiveId}.json`;

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();

    URL.revokeObjectURL(url);
  };

  const scoreLabel =
    postureScore === null
      ? 'Not Assessed'
      : `${postureScore} / 100`;

  const protocolLabel =
    detectedProtocol &&
    detectedProtocol !== 'UNKNOWN' &&
    detectedProtocol !== 'NONE'
      ? detectedProtocol
      : 'No email protocol detected';

  const assessmentDescription = hasEmailSignals
    ? 'Email traffic was identified and the cryptographic security pipeline was applicable to this capture.'
    : 'No identifiable SMTP, SMTPS, IMAP, IMAPS, POP3, or POP3S traffic was detected. Cryptographic email security was therefore not assessed.';

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#f8fbff] text-slate-900">
      <div className="relative overflow-hidden">
        {/* Atmospheric background */}
        <div className="pointer-events-none absolute inset-0">
          <div className="absolute -top-32 right-0 h-96 w-96 rounded-full bg-blue-100/50 blur-3xl" />
          <div className="absolute top-80 -left-32 h-80 w-80 rounded-full bg-cyan-100/35 blur-3xl" />
        </div>

        <div className="relative mx-auto max-w-7xl px-6 py-8 lg:px-10">
          {/* Header */}
          <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-blue-100 bg-blue-50 px-3 py-1.5 text-xs font-bold uppercase tracking-wider text-[#0B5ED7]">
                <FileText className="h-3.5 w-3.5" />
                Forensic Report
              </div>

              <h1 className="text-3xl font-black tracking-tight text-slate-950">
                Forensic Reports
              </h1>

              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
                Audit exports and machine-readable evidence packages for
                this analysis session.
              </p>

              <p className="mt-2 font-mono text-xs text-[#0B5ED7]">
                Session: {effectiveId}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={handleDownloadJSON}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-bold text-slate-700 shadow-sm transition hover:border-blue-200 hover:bg-blue-50"
              >
                <Download className="h-4 w-4" />
                Export JSON
              </button>

              <a
                href={exportReportPDFUrl(effectiveId)}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 rounded-xl bg-[#0B5ED7] px-4 py-2.5 text-sm font-bold text-white shadow-lg shadow-[0_8px_24px_rgba(11,94,215,0.20)] transition hover:bg-[#084FB8]"
              >
                <FileText className="h-4 w-4" />
                Download PDF Report
              </a>
            </div>
          </div>

          {/* Assessment state */}
          <div
            className={`mt-8 overflow-hidden rounded-3xl border ${
              hasEmailSignals
                ? 'border-emerald-100 bg-emerald-50/50'
                : 'border-blue-100 bg-blue-50/50'
            }`}
          >
            <div className="p-6 lg:p-7">
              <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                <div className="flex gap-4">
                  <div
                    className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl ${
                      hasEmailSignals
                        ? 'bg-emerald-100 text-emerald-600'
                        : 'bg-blue-100 text-[#0B5ED7]'
                    }`}
                  >
                    {hasEmailSignals ? (
                      <ShieldCheck className="h-6 w-6" />
                    ) : (
                      <ShieldAlert className="h-6 w-6" />
                    )}
                  </div>

                  <div>
                    <h2 className="text-lg font-black text-slate-900">
                      {hasEmailSignals
                        ? 'Email Security Assessment'
                        : 'Email Security Not Assessed'}
                    </h2>

                    <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
                      {assessmentDescription}
                    </p>
                  </div>
                </div>

                <div
                  className={`shrink-0 rounded-full px-4 py-2 text-xs font-black uppercase tracking-wider ${
                    hasEmailSignals
                      ? 'bg-emerald-100 text-emerald-700'
                      : 'bg-blue-100 text-[#0B5ED7]'
                  }`}
                >
                  {hasEmailSignals ? 'ASSESSED' : 'NOT ASSESSED'}
                </div>
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <section className="mt-8">
            <div className="mb-4">
              <h2 className="text-lg font-black text-slate-900">
                Executive Summary
              </h2>
              <p className="mt-1 text-sm text-slate-500">
                Evidence-backed summary of the captured session.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {/* Filename */}
              <SummaryCard
                icon={<FileText className="h-5 w-5" />}
                label="Target Filename"
                value={report?.session?.filename || 'N/A'}
              />

              {/* Status */}
              <SummaryCard
                icon={<ShieldCheck className="h-5 w-5" />}
                label="Analysis Status"
                value={report?.session?.status || 'UNKNOWN'}
                valueClass="text-emerald-600"
              />

              {/* Streams */}
              <SummaryCard
                icon={<Network className="h-5 w-5" />}
                label="Reassembled Streams"
                value={String(totalStreams)}
              />

              {/* Protocol */}
              <SummaryCard
                icon={<Mail className="h-5 w-5" />}
                label="Detected Email Protocol"
                value={protocolLabel}
                valueClass={
                  hasEmailSignals
                    ? 'text-[#0B5ED7]'
                    : 'text-slate-500'
                }
              />

              {/* Score */}
              <SummaryCard
                icon={<ShieldCheck className="h-5 w-5" />}
                label="Cryptographic Posture Score"
                value={scoreLabel}
                valueClass={
                  postureScore === null
                    ? 'text-slate-500'
                    : 'text-emerald-600'
                }
              />

              {/* Risk */}
              <SummaryCard
                icon={<AlertTriangle className="h-5 w-5" />}
                label="Risk Classification"
                value={riskClass || 'Not Assessed'}
                valueClass={
                  riskClass
                    ? 'text-slate-900'
                    : 'text-slate-500'
                }
              />
            </div>
          </section>

          {/* Technical scope */}
          <section className="mt-8">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <InfoCard
                icon={<LockKeyhole className="h-5 w-5" />}
                title="TLS Evidence"
                value={
                  hasEmailSignals
                    ? (
                        report?.protocol_summary?.has_tls
                          ? 'TLS evidence present'
                          : 'No TLS evidence observed'
                      )
                    : 'Not Assessed'
                }
              />

              <InfoCard
                icon={<ShieldCheck className="h-5 w-5" />}
                title="Verified Findings"
                value={
                  hasEmailSignals
                    ? String(findings.length)
                    : '0 — Not Assessed'
                }
              />

              <InfoCard
                icon={<AlertTriangle className="h-5 w-5" />}
                title="Anomaly Detection"
                value={
                  anomaly === null
                    ? 'Not Assessed'
                    : anomaly
                      ? 'Anomaly detected'
                      : 'No anomaly detected'
                }
              />
            </div>
          </section>

          {/* No email signals explanation */}
          {!hasEmailSignals && (
            <section className="mt-8 rounded-3xl border border-blue-100 bg-blue-50/45 p-6 lg:p-7">
              <div className="flex gap-4">
                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-white text-[#0B5ED7] shadow-sm">
                  <Network className="h-5 w-5" />
                </div>

                <div>
                  <h3 className="text-base font-black text-slate-900">
                    No Email or TLS Signals Detected
                  </h3>

                  <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-600">
                    This capture contains network traffic, but the available
                    evidence does not identify an SMTP, SMTPS, IMAP, IMAPS,
                    POP3, or POP3S session. A TCP stream count alone does not
                    establish an email-security assessment.
                  </p>

                  <p className="mt-3 text-xs font-semibold text-slate-500">
                    Posture score, cryptographic findings, ML risk
                    classification, and anomaly assessment are therefore
                    shown as <span className="font-black text-[#0B5ED7]">
                      Not Assessed
                    </span> rather than being inferred from unrelated traffic.
                  </p>
                </div>
              </div>
            </section>
          )}

          {/* Methodology */}
          <section className="mt-8 rounded-[24px] border border-blue-100/90 bg-white/90 p-6 shadow-[0_14px_45px_rgba(15,76,160,0.07)] backdrop-blur-xl">
            <h3 className="text-sm font-black uppercase tracking-wider text-[#0B5ED7]">
              Assessment Basis
            </h3>

            <p className="mt-3 text-sm leading-6 text-slate-600">
              MailRakhwala reports cryptographic security results only when
              applicable email traffic is identified in the captured
              evidence. Unavailable or non-applicable measurements are not
              converted into security scores or findings.
            </p>

            {report?.methodology_disclaimer && (
              <p className="mt-3 border-t border-blue-100 pt-3 text-xs leading-5 text-slate-400">
                {report.methodology_disclaimer}
              </p>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}

function SummaryCard({
  icon,
  label,
  value,
  valueClass = 'text-slate-900',
}) {
  return (
    <div className="rounded-2xl border border-blue-100 bg-white/90 p-5 shadow-sm transition hover:border-blue-200 hover:shadow-md">
      <div className="flex items-start gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-blue-50 text-[#0B5ED7]">
          {icon}
        </div>

        <div className="min-w-0">
          <span className="block text-xs font-bold uppercase tracking-wider text-slate-400">
            {label}
          </span>

          <span
            className={`mt-1 block break-words text-sm font-black ${valueClass}`}
          >
            {value}
          </span>
        </div>
      </div>
    </div>
  );
}

function InfoCard({
  icon,
  title,
  value,
}) {
  return (
    <div className="rounded-2xl border border-blue-100 bg-white/90 p-5 shadow-sm">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-50 text-[#0B5ED7]">
          {icon}
        </div>

        <div>
          <span className="block text-xs font-bold uppercase tracking-wider text-slate-400">
            {title}
          </span>

          <span className="mt-1 block text-sm font-black text-slate-800">
            {value}
          </span>
        </div>
      </div>
    </div>
  );
}