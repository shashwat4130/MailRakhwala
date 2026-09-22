import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  FileText,
  Layers3,
  LockKeyhole,
  Mail,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Upload,
  Activity,
} from 'lucide-react';
import { getActiveAnalysisId, getAnalysisReport } from '../services/api';

const Card = ({ children, className = '', onClick }) => (
  <div
    onClick={onClick}
    className={[
      'rounded-3xl border border-violet-100 bg-white shadow-[0_18px_55px_rgba(71,38,130,0.08)]',
      onClick ? 'cursor-pointer transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_24px_70px_rgba(71,38,130,0.13)]' : '',
      className,
    ].join(' ')}
  >
    {children}
  </div>
);

const SectionEyebrow = ({ children }) => (
  <div className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.18em] text-violet-600">
    <span className="h-1.5 w-1.5 rounded-full bg-violet-500" />
    {children}
  </div>
);

const OverviewCard = ({ icon: Icon, label, value, detail, tone = 'violet' }) => {
  const tones = {
    violet: 'bg-violet-50 text-violet-600',
    amber: 'bg-amber-50 text-amber-600',
    emerald: 'bg-emerald-50 text-emerald-600',
    slate: 'bg-slate-100 text-slate-600',
  };

  return (
    <div className="rounded-2xl border border-slate-100 bg-slate-50/70 p-4 transition-all duration-200 hover:border-violet-100 hover:bg-white">
      <div className="flex items-start justify-between gap-3">
        <div className={`flex h-9 w-9 items-center justify-center rounded-xl ${tones[tone]}`}>
          <Icon className="h-4.5 w-4.5" />
        </div>
      </div>
      <p className="mt-4 text-[11px] font-semibold uppercase tracking-[0.13em] text-slate-400">
        {label}
      </p>
      <p className="mt-1 truncate text-xl font-black tracking-tight text-slate-900">
        {value}
      </p>
      <p className="mt-1 truncate text-xs text-slate-500">{detail}</p>
    </div>
  );
};

const ActionCard = ({ icon: Icon, title, description, buttonLabel, tone, onClick }) => {
  const styles = {
    violet: {
      icon: 'bg-violet-50 text-violet-600 border-violet-100',
      button: 'bg-violet-600 text-white hover:bg-violet-700 shadow-violet-200',
      line: 'group-hover:text-violet-600',
    },
    amber: {
      icon: 'bg-amber-50 text-amber-600 border-amber-100',
      button: 'bg-amber-500 text-white hover:bg-amber-600 shadow-amber-200',
      line: 'group-hover:text-amber-600',
    },
    slate: {
      icon: 'bg-slate-100 text-slate-700 border-slate-200',
      button: 'bg-slate-900 text-white hover:bg-slate-800 shadow-slate-200',
      line: 'group-hover:text-slate-900',
    },
  };

  const style = styles[tone];

  return (
    <Card className="group flex h-full flex-col p-6 hover:-translate-y-1 hover:scale-[1.01] hover:shadow-[0_24px_70px_rgba(71,38,130,0.16)]" onClick={onClick}>
      <div className={`flex h-11 w-11 items-center justify-center rounded-2xl border transition-all duration-300 group-hover:scale-110 group-hover:-rotate-3 ${style.icon}`}>
        <Icon className="h-5 w-5 transition-transform duration-300 group-hover:scale-110" />
      </div>

      <h3 className={`mt-5 text-lg font-black tracking-tight text-slate-900 transition-colors ${style.line}`}>
        {title}
      </h3>

      <p className="mt-2 min-h-[42px] text-sm leading-6 text-slate-500">
        {description}
      </p>

      <button
        type="button"
        onClick={(event) => {
          event.stopPropagation();
          onClick();
        }}
        className={`mt-6 inline-flex w-full items-center justify-center gap-2 rounded-xl px-4 py-3 text-sm font-bold shadow-lg transition-all active:scale-[0.98] ${style.button}`}
      >
        {buttonLabel}
        <ArrowRight className="h-4 w-4" />
      </button>
    </Card>
  );
};

export default function Dashboard() {
  const navigate = useNavigate();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const resolveCurrentId = () =>
    getActiveAnalysisId() ||
    localStorage.getItem('active_analysis_id') ||
    localStorage.getItem('analysis_id') ||
    null;

  const [analysisId, setAnalysisId] = useState(resolveCurrentId);

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
      setReport(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    getAnalysisReport(currentId)
      .then((data) => {
        setReport(data);
      })
      .catch((err) => {
        console.error('Failed to load dashboard report:', err);
        setError(
          err.response?.data?.detail ||
            'The security report could not be loaded.'
        );
      })
      .finally(() => setLoading(false));
  }, [analysisId]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-white">
        <div className="flex flex-col items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-violet-50 text-violet-600">
            <RefreshCw className="h-5 w-5 animate-spin" />
          </div>
          <p className="text-sm font-semibold text-slate-600">
            Loading security report...
          </p>
        </div>
      </div>
    );
  }

  const effectiveId = analysisId || resolveCurrentId();

  if (!effectiveId) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-white p-6">
        <Card className="w-full max-w-lg p-10 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-violet-50 text-violet-600">
            <ShieldAlert className="h-7 w-7" />
          </div>
          <h2 className="mt-5 text-2xl font-black tracking-tight text-slate-900">
            No active analysis
          </h2>
          <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">
            Upload and process a PCAP capture to generate the security dashboard.
          </p>
          <button
            type="button"
            onClick={() => navigate('/')}
            className="mt-7 inline-flex items-center gap-2 rounded-full bg-violet-600 px-6 py-3 text-sm font-bold text-white shadow-lg shadow-violet-200 transition hover:bg-violet-700"
          >
            <Upload className="h-4 w-4" />
            Capture Ingestion
          </button>
        </Card>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-white p-6">
        <Card className="w-full max-w-lg p-10 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-red-50 text-red-500">
            <AlertTriangle className="h-7 w-7" />
          </div>
          <h2 className="mt-5 text-2xl font-black tracking-tight text-slate-900">
            Report unavailable
          </h2>
          <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">
            {error}
          </p>
          <button
            type="button"
            onClick={() => navigate('/')}
            className="mt-7 rounded-full bg-slate-900 px-6 py-3 text-sm font-bold text-white transition hover:bg-slate-800"
          >
            Return to Capture Ingestion
          </button>
        </Card>
      </div>
    );
  }

  const totalStreams = report?.session?.total_streams ?? 0;
  const findings = Array.isArray(report?.compliance_findings)
    ? report.compliance_findings
    : [];

  const detectedProtocol =
    report?.protocol_summary?.detected_protocol || 'Not detected';

  const hasTls = Boolean(report?.protocol_summary?.has_tls);

  const normalizedProtocol = String(detectedProtocol).trim().toUpperCase();

  const hasEmailSignals =
    totalStreams > 0 &&
    ['SMTP', 'SMTPS', 'IMAP', 'IMAPS', 'POP3', 'POP3S'].includes(
      normalizedProtocol
    );

  const rawScore = report?.posture_report?.posture_score;
  const hasValidScore =
    typeof rawScore === 'number' && Number.isFinite(rawScore);

  const postureScore = hasEmailSignals && hasValidScore ? rawScore : null;

  const riskClass =
    report?.risk_classification?.predicted_risk_class ||
    report?.risk_classification?.risk_class ||
    null;

  const anomalyValue =
    typeof report?.anomaly_detection?.is_anomaly === 'boolean'
      ? report.anomaly_detection.is_anomaly
      : null;

  const seriousIssues = findings.filter((finding) => {
    const severity = String(finding?.severity ?? '').trim().toUpperCase();
    return severity === 'CRITICAL' || severity === 'HIGH';
  }).length;

  const filename = report?.session?.filename || 'Capture file';
  const fileSizeBytes = report?.session?.filesize_bytes;
  const fileSize =
    typeof fileSizeBytes === 'number'
      ? `${(fileSizeBytes / 1024).toFixed(1)} KB`
      : 'Not available';

  const standardChecked =
    report?.standard_checked || 'Not available';

  const scoreRing =
    postureScore === null
      ? 0
      : Math.max(0, Math.min(100, postureScore));

  const scoreStatus =
    postureScore === null
      ? 'Not Assessed'
      : postureScore >= 85
        ? 'Strong posture'
        : postureScore >= 60
          ? 'Needs attention'
          : 'Review required';

  const scoreMessage =
    postureScore === null
      ? 'No observable email/TLS traffic was available for cryptographic assessment.'
      : 'Authoritative posture score returned by the security analysis backend.';

  const riskDisplay = riskClass || 'Not available';
  const anomalyDisplay =
    anomalyValue === null
      ? 'Not available'
      : anomalyValue
        ? 'Unusual activity detected'
        : 'No anomaly detected';

  const protocolDisplay = hasEmailSignals
    ? detectedProtocol
    : 'Not assessed';

  const reportCardDescription =
    `${filename} · ${fileSize} · ${totalStreams} stream${totalStreams === 1 ? '' : 's'} inspected.`;

  return (
    <div className="relative min-h-full overflow-hidden bg-white px-4 py-5 sm:px-6 lg:px-8">
      <div className="pointer-events-none absolute -left-32 top-24 h-80 w-80 rounded-full bg-violet-200/25 blur-3xl" />
      <div className="pointer-events-none absolute -right-40 bottom-20 h-96 w-96 rounded-full bg-purple-200/20 blur-3xl" />

      <div className="relative mx-auto max-w-[1280px] space-y-6">
        {/* Dashboard header */}
        <header className="flex flex-col gap-5 border-b border-violet-100 pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <SectionEyebrow>Security command center</SectionEyebrow>
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-3xl font-black tracking-[-0.035em] text-slate-950 sm:text-4xl">
                Security Overview
              </h1>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[11px] font-bold uppercase tracking-wide text-emerald-700">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Analysis complete
              </span>
            </div>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
              A clear view of what was captured, what the backend assessed, and where to investigate next.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="rounded-2xl border border-slate-200 bg-white px-4 py-2.5 shadow-sm">
              <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">
                Capture
              </p>
              <p className="mt-0.5 max-w-[260px] truncate text-sm font-bold text-slate-800">
                {filename}
              </p>
            </div>

            <button
              type="button"
              onClick={() => navigate('/')}
              className="inline-flex items-center gap-2 rounded-2xl border border-violet-200 bg-white px-4 py-3 text-sm font-bold text-violet-700 shadow-sm transition hover:border-violet-300 hover:bg-violet-50"
            >
              <Upload className="h-4 w-4" />
              New capture
            </button>
          </div>
        </header>

        {/* Security overview */}
        <section>
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h2 className="text-base font-black text-slate-900">
                Security overview
              </h2>
              <p className="mt-0.5 text-xs text-slate-500">
                The four things to understand first.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <OverviewCard
              icon={ShieldCheck}
              label="Posture"
              value={postureScore === null ? 'Not Assessed' : `${postureScore}/100`}
              detail={scoreStatus}
              tone={postureScore === null ? 'slate' : 'violet'}
            />
            <OverviewCard
              icon={AlertTriangle}
              label="Findings"
              value={findings.length}
              detail={`${seriousIssues} serious issue${seriousIssues === 1 ? '' : 's'}`}
              tone={findings.length > 0 ? 'amber' : 'emerald'}
            />
            <OverviewCard
              icon={Activity}
              label="Risk / anomaly"
              value={riskDisplay}
              detail={anomalyDisplay}
              tone={riskClass ? 'violet' : 'slate'}
            />
            <OverviewCard
              icon={Mail}
              label="Protocol"
              value={protocolDisplay}
              detail={`${totalStreams} total stream${totalStreams === 1 ? '' : 's'}`}
              tone={hasEmailSignals ? 'emerald' : 'slate'}
            />
          </div>
        </section>

        {/* Main posture panel */}
        <Card className="overflow-hidden">
          <div className="grid lg:grid-cols-[1.1fr_1.9fr]">
            <div className="relative overflow-hidden bg-gradient-to-br from-violet-700 via-violet-600 to-purple-700 p-7 text-white sm:p-8">
              <div className="pointer-events-none absolute -right-16 -top-16 h-48 w-48 rounded-full bg-white/10 blur-2xl" />
              <div className="pointer-events-none absolute -bottom-20 -left-10 h-44 w-44 rounded-full bg-purple-300/15 blur-3xl" />

              <div className="relative">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-violet-200">
                      Cryptographic posture
                    </p>
                    <p className="mt-1 text-sm font-medium text-violet-100">
                      Overall assessment
                    </p>
                  </div>
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white/10 ring-1 ring-white/15">
                    <LockKeyhole className="h-5 w-5" />
                  </div>
                </div>

                <div className="mt-8 flex items-center gap-6">
                  <div
                    className="relative flex h-32 w-32 shrink-0 items-center justify-center rounded-full"
                    style={{
                      background: `conic-gradient(#ffffff ${scoreRing}%, rgba(255,255,255,0.18) ${scoreRing}% 100%)`,
                    }}
                  >
                    <div className="flex h-[106px] w-[106px] flex-col items-center justify-center rounded-full bg-violet-700">
                      {postureScore === null ? (
                        <span className="px-3 text-center text-sm font-black leading-tight">
                          Not Assessed
                        </span>
                      ) : (
                        <>
                          <span className="text-3xl font-black tracking-tight">
                            {postureScore}
                          </span>
                          <span className="text-[10px] font-semibold uppercase tracking-wider text-violet-200">
                            out of 100
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  <div className="min-w-0">
                    <span className="inline-flex rounded-full bg-white/12 px-3 py-1 text-xs font-bold text-white ring-1 ring-white/15">
                      {scoreStatus}
                    </span>
                    <p className="mt-3 text-sm leading-6 text-violet-100">
                      {scoreMessage}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="p-7 sm:p-8">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-violet-600">
                    Capture intelligence
                  </p>
                  <h2 className="mt-1 text-xl font-black tracking-tight text-slate-900">
                    What the analysis found
                  </h2>
                </div>
                <Sparkles className="h-5 w-5 text-violet-400" />
              </div>

              <div className="mt-6 grid grid-cols-2 gap-3">
                <div className="rounded-2xl border border-slate-100 bg-slate-50 p-4">
                  <div className="flex items-center gap-2 text-violet-600">
                    <Network className="h-4 w-4" />
                    <span className="text-[11px] font-bold uppercase tracking-wide">
                      Streams
                    </span>
                  </div>
                  <p className="mt-2 text-2xl font-black text-slate-900">
                    {totalStreams}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    Total reconstructed streams
                  </p>
                </div>

                <div className="rounded-2xl border border-slate-100 bg-slate-50 p-4">
                  <div className="flex items-center gap-2 text-amber-600">
                    <AlertTriangle className="h-4 w-4" />
                    <span className="text-[11px] font-bold uppercase tracking-wide">
                      Findings
                    </span>
                  </div>
                  <p className="mt-2 text-2xl font-black text-slate-900">
                    {findings.length}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    Deterministic observations
                  </p>
                </div>

                <div className="rounded-2xl border border-slate-100 bg-slate-50 p-4">
                  <div className="flex items-center gap-2 text-emerald-600">
                    <Mail className="h-4 w-4" />
                    <span className="text-[11px] font-bold uppercase tracking-wide">
                      Protocol
                    </span>
                  </div>
                  <p className="mt-2 truncate text-xl font-black text-slate-900">
                    {protocolDisplay}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    Detected by the analysis pipeline
                  </p>
                </div>

                <div className="rounded-2xl border border-slate-100 bg-slate-50 p-4">
                  <div className="flex items-center gap-2 text-slate-600">
                    <Layers3 className="h-4 w-4" />
                    <span className="text-[11px] font-bold uppercase tracking-wide">
                      Standard
                    </span>
                  </div>
                  <p className="mt-2 truncate text-sm font-black text-slate-900">
                    {standardChecked}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    Reported by the backend
                  </p>
                </div>
              </div>
            </div>
          </div>
        </Card>

        {/* Bottom action cards */}
        <section>
          <div className="mb-3 flex items-end justify-between">
            <div>
              <h2 className="text-base font-black text-slate-900">
                Continue investigation
              </h2>
              <p className="mt-0.5 text-xs text-slate-500">
                Three focused views for the next step.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <ActionCard
              icon={Network}
              title="Stream Analysis"
              description="See every connection and understand what happened during the captured session."
              buttonLabel="Open Stream Analysis"
              tone="violet"
              onClick={() => navigate('/analysis')}
            />

            <ActionCard
              icon={AlertTriangle}
              title="Findings & CVEs"
              description="Review the security problems identified by the real analysis and their supporting evidence."
              buttonLabel="View Findings"
              tone="amber"
              onClick={() => navigate('/findings')}
            />

            <ActionCard
              icon={FileText}
              title="Forensic Report"
              description={reportCardDescription}
              buttonLabel="View Forensic Report"
              tone="slate"
              onClick={() => navigate('/reports')}
            />
          </div>
        </section>

        {/* Compact metadata footer */}
        <Card className="p-5">
          <div className="grid grid-cols-2 gap-4 text-xs sm:grid-cols-4">
            <div>
              <p className="font-semibold uppercase tracking-wide text-slate-400">
                Capture
              </p>
              <p className="mt-1 truncate font-bold text-slate-800">{filename}</p>
            </div>
            <div>
              <p className="font-semibold uppercase tracking-wide text-slate-400">
                File size
              </p>
              <p className="mt-1 font-bold text-slate-800">{fileSize}</p>
            </div>
            <div>
              <p className="font-semibold uppercase tracking-wide text-slate-400">
                Analysis ID
              </p>
              <p className="mt-1 truncate font-mono font-bold text-slate-800">
                {effectiveId}
              </p>
            </div>
            <div>
              <p className="font-semibold uppercase tracking-wide text-slate-400">
                TLS observed
              </p>
              <p className="mt-1 font-bold text-slate-800">
                {hasTls ? 'Yes' : 'No'}
              </p>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
