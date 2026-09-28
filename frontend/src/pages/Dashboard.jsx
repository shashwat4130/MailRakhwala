import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Download,
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
  X,
} from 'lucide-react';
import {
  downloadAnalysisJson,
  downloadAnalysisPdf,
  getActiveAnalysisId,
  getAnalysisReport,
} from '../services/api';

const Card = ({ children, className = '', onClick }) => (
  <div
    onClick={onClick}
    className={[
      'rounded-3xl border border-blue-100/80 bg-white shadow-[0_18px_55px_rgba(15,76,160,0.09)] ring-1 ring-blue-50/80',
      onClick ? 'cursor-pointer transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_24px_70px_rgba(15,76,160,0.16)]' : '',
      className,
    ].join(' ')}
  >
    {children}
  </div>
);

const SectionEyebrow = ({ children }) => (
  <div className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.18em] text-blue-600">
    <span className="h-1.5 w-1.5 rounded-full bg-blue-500" />
    {children}
  </div>
);

const OverviewCard = ({ icon: Icon, label, value, detail, tone = 'blue', action }) => {
  const tones = {
    blue: 'bg-blue-50 text-blue-600',
    violet: 'bg-blue-50 text-blue-600',
    amber: 'bg-amber-50 text-amber-600',
    emerald: 'bg-emerald-50 text-emerald-600',
    slate: 'bg-slate-100 text-slate-600',
  };

  return (
    <div className="rounded-2xl border border-blue-100/70 bg-gradient-to-br from-white to-blue-50/60 p-4 transition-all duration-200 hover:border-blue-200 hover:bg-white hover:shadow-[0_10px_30px_rgba(37,99,235,0.08)]">
      <div className="flex items-start justify-between gap-3">
        <div className={`flex h-9 w-9 items-center justify-center rounded-xl ${tones[tone]}`}>
          <Icon className="h-4.5 w-4.5" />
        </div>
        {action}
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
      icon: 'bg-blue-50 text-blue-600 border-blue-100',
      button: 'bg-gradient-to-r from-blue-700 to-cyan-600 text-white hover:from-blue-800 hover:to-cyan-700 shadow-blue-200',
      line: 'group-hover:text-blue-600',
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
    <Card className="group flex h-full flex-col p-6 hover:-translate-y-1.5 hover:scale-[1.01] hover:shadow-[0_28px_80px_rgba(15,76,160,0.20)]" onClick={onClick}>
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

const ScoreAnalysisModal = ({ postureReport, onClose, onViewFindings }) => {
  const baseScore =
    typeof postureReport?.base_score === 'number' && Number.isFinite(postureReport.base_score)
      ? postureReport.base_score
      : 100;

  const deductions = Array.isArray(postureReport?.deductions)
    ? postureReport.deductions
    : [];

  const calculatedPenalty = deductions.reduce((sum, deduction) => {
    const penalty = Number(deduction?.penalty);
    return Number.isFinite(penalty) ? sum + penalty : sum;
  }, 0);

  const totalPenalty =
    typeof postureReport?.total_penalty === 'number' && Number.isFinite(postureReport.total_penalty)
      ? postureReport.total_penalty
      : calculatedPenalty;

  const finalScore =
    typeof postureReport?.posture_score === 'number' && Number.isFinite(postureReport.posture_score)
      ? postureReport.posture_score
      : Math.max(0, Math.min(100, baseScore - totalPenalty));

  const severity = String(postureReport?.severity ?? '').toUpperCase();
  const scoreStatus = finalScore >= 85 ? 'Strong posture' : finalScore >= 60 ? 'Needs attention' : 'Review required';
  const severityLabel = severity ? severity.charAt(0) + severity.slice(1).toLowerCase() : scoreStatus;

  const pointsRemaining = Math.max(0, Math.min(100, finalScore));
  const scoreExplanation =
    deductions.length === 0
      ? `No verified security issue reduced the starting score of ${baseScore}.`
      : `MailRakhwala started at ${baseScore} points and removed ${totalPenalty} points for verified security issues found in the capture.`;

  const simpleExplanation = (deduction) => {
    const property = String(deduction?.observed_property || '').toLowerCase();
    const value = String(deduction?.observed_value || '').toUpperCase();

    if (property === 'starttls.state' && value.includes('PLAINTEXT_CONTINUATION')) {
      return 'The mail server offered STARTTLS, but this captured connection did not switch to encrypted TLS. Mail traffic therefore remained visible in plaintext.';
    }
    if (property === 'transport.security' && value.startsWith('PLAINTEXT_')) {
      return 'Email traffic was captured without TLS encryption. This means the email data was not protected while travelling across the network.';
    }
    if (property === 'tls.version') {
      return `The captured connection used ${deduction?.observed_value || 'an unsupported TLS version'}, which does not meet the required security level.`;
    }
    if (property === 'tls.cipher_suite') {
      return `The captured connection used the ${deduction?.observed_value || 'observed'} encryption method, which does not meet the configured cipher security requirement.`;
    }
    if (property === 'kex.has_forward_secrecy' && value === 'FALSE') {
      return 'The connection did not use forward secrecy, so a recorded session has weaker protection if long-term keys are exposed later.';
    }
    if (property === 'cert.validity') {
      return `The server certificate was ${deduction?.observed_value || 'not in a valid state'} when it was observed in the capture.`;
    }
    if (property === 'cert.public_key_bits') {
      return `The certificate used a ${deduction?.observed_value || 'smaller-than-required'}-bit public key, below the configured minimum.`;
    }
    if (property === 'identity.sni_vs_san') {
      return 'The server name observed during the connection did not match the identity presented by the certificate.';
    }

    return deduction?.description || 'A verified security issue caused this deduction.';
  };

  const readableEvidence = (property, value) => {
    const raw = String(value ?? 'Unavailable');
    const upper = raw.toUpperCase();

    if (property === 'starttls.state' && upper.includes('PLAINTEXT_CONTINUATION')) {
      return 'STARTTLS advertised → connection stayed unencrypted';
    }
    if (property === 'transport.security' && upper.startsWith('PLAINTEXT_')) {
      return 'Email traffic was observed without TLS';
    }
    if (upper === 'TRUE') return 'Yes';
    if (upper === 'FALSE') return 'No';
    if (upper === 'UNAVAILABLE') return 'Not available in the capture';
    return raw;
  };

  useEffect(() => {
    const handleEscape = (event) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleEscape);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', handleEscape);
      document.body.style.overflow = previousOverflow;
    };
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-sm sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="score-analysis-title"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="dashboard-modal-enter flex max-h-[90vh] w-full max-w-2xl flex-col overflow-hidden rounded-[28px] border border-blue-100 bg-white shadow-[0_30px_100px_rgba(15,76,160,0.24)]">
        <div className="shrink-0 border-b border-slate-100 bg-gradient-to-r from-blue-50 via-white to-cyan-50 px-6 py-5 sm:px-7">
          <div>
            <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.18em] text-blue-600">
              <BarChart3 className="h-4 w-4" />
              Score explanation
            </div>
            <h2 id="score-analysis-title" className="mt-1 text-2xl font-black tracking-tight text-slate-950">
              Why did I get {finalScore}/100?
            </h2>
            <p className="mt-1 text-sm text-slate-500">
              See what MailRakhwala found and how many points each issue removed.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close score analysis"
            className="rounded-xl border border-slate-200 bg-white p-2 text-slate-500 transition hover:border-blue-200 hover:bg-blue-50 hover:text-blue-700"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="min-h-0 overflow-y-auto p-5 sm:p-7">
          <div className="grid gap-4 sm:grid-cols-[auto_1fr]">
            <div className="flex h-28 w-28 shrink-0 flex-col items-center justify-center rounded-full bg-[#061A3A] text-white shadow-[0_12px_35px_rgba(6,26,58,0.22)]">
              <span className="text-3xl font-black leading-none">{finalScore}</span>
              <span className="mt-1 text-[10px] font-bold uppercase tracking-wider text-blue-200">/ 100</span>
            </div>
            <div className="rounded-2xl border border-blue-100 bg-blue-50/60 p-5">
              <p className="text-xs font-bold uppercase tracking-[0.14em] text-blue-600">Your security score</p>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <h3 className="text-xl font-black text-slate-900">{scoreStatus}</h3>
                {severity && (
                  <span className="rounded-full border border-blue-200 bg-white px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide text-blue-700">
                    {severityLabel} risk
                  </span>
                )}
              </div>
              <p className="mt-2 text-sm leading-6 text-slate-600">
                {scoreExplanation}
              </p>
            </div>
          </div>

          <div className="mt-7">
            <div className="flex items-end justify-between gap-4">
              <div>
                <p className="text-xs font-bold uppercase tracking-[0.14em] text-blue-600">Why points were removed</p>
                <h3 className="mt-1 text-lg font-black text-slate-950">Security issues found</h3>
              </div>
              <div className="text-right">
                <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">Total deduction</p>
                <p className="text-lg font-black text-rose-600">−{totalPenalty}</p>
              </div>
            </div>

            {deductions.length === 0 ? (
              <div className="mt-4 rounded-2xl border border-emerald-100 bg-emerald-50 p-5">
                <div className="flex gap-3">
                  <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" />
                  <div>
                    <p className="font-bold text-emerald-900">No verified deductions were applied.</p>
                    <p className="mt-1 text-sm leading-6 text-emerald-800/80">
                      The posture engine did not find an evidence-backed non-compliant condition that reduced the score.
                    </p>
                  </div>
                </div>
              </div>
            ) : (
              <div className="mt-4 space-y-3">
                {deductions.map((deduction, index) => {
                  const penalty = Number(deduction?.penalty);
                  const observedProperty = deduction?.observed_property;
                  const observedValue = deduction?.observed_value;
                  return (
                    <div
                      key={deduction?.finding_id || `${deduction?.rule_id || 'deduction'}-${index}`}
                      className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm transition hover:border-blue-200 hover:shadow-[0_10px_30px_rgba(15,76,160,0.08)]"
                    >
                      <div className="flex items-start gap-3">
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-rose-50 text-rose-600">
                          <ShieldAlert className="h-4 w-4" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-start justify-between gap-2">
                            <div>
                              <h4 className="font-bold text-slate-900">
                                {deduction?.title || deduction?.rule_id || 'Security deduction'}
                              </h4>
                              <p className="mt-1 text-xs font-semibold text-slate-500">
                                This issue reduced your score by {Number.isFinite(penalty) ? penalty : 0} point{Number.isFinite(penalty) && penalty === 1 ? '' : 's'}.
                              </p>
                              {deduction?.rule_id && (
                                <p className="mt-2 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                                  Security rule: {deduction.rule_id}
                                </p>
                              )}
                            </div>
                            <span className="shrink-0 rounded-full bg-rose-50 px-2.5 py-1 text-xs font-black text-rose-700">
                              −{Number.isFinite(penalty) ? penalty : 0}
                            </span>
                          </div>
                          <div className="mt-4 rounded-xl border border-amber-100 bg-amber-50/70 p-4">
                            <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-amber-700">What happened?</p>
                            <p className="mt-1 text-sm leading-6 text-slate-700">
                              {simpleExplanation(deduction)}
                            </p>
                          </div>
                          {(observedProperty || observedValue !== undefined) && (
                            <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
                              <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-500">What was detected</p>
                              <div className="mt-3 space-y-2">
                                <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
                                  <span className="shrink-0 text-xs font-semibold text-slate-500">{observedProperty || 'Observed value'}</span>
                                  <span className="min-w-0 break-words text-left text-xs font-semibold leading-5 text-slate-800 sm:max-w-[65%] sm:text-right">{readableEvidence(observedProperty, observedValue)}</span>
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="mt-6 rounded-2xl border border-blue-100 bg-gradient-to-r from-slate-50 to-blue-50/60 p-5">
            <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-blue-600">Your score, simply explained</p>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <div className="rounded-xl border border-slate-200 bg-white p-4">
                <p className="text-[10px] font-bold uppercase tracking-wide text-slate-400">Started with</p>
                <p className="mt-1 text-2xl font-black text-slate-900">{baseScore}</p>
                <p className="text-xs text-slate-500">points</p>
              </div>
              <div className="rounded-xl border border-rose-100 bg-rose-50/60 p-4">
                <p className="text-[10px] font-bold uppercase tracking-wide text-rose-500">Points lost</p>
                <p className="mt-1 text-2xl font-black text-rose-700">−{totalPenalty}</p>
                <p className="text-xs text-rose-600/80">from verified issues</p>
              </div>
              <div className="rounded-xl border border-blue-100 bg-blue-50 p-4">
                <p className="text-[10px] font-bold uppercase tracking-wide text-blue-600">Your score</p>
                <p className="mt-1 text-2xl font-black text-blue-900">{pointsRemaining}/100</p>
                <p className="text-xs text-blue-700/80">{scoreStatus}</p>
              </div>
            </div>
            <div className="mt-4 rounded-xl bg-white px-4 py-3 ring-1 ring-blue-100">
              <p className="text-sm font-semibold text-slate-700">
                {baseScore} starting points − {totalPenalty} points lost = <span className="font-black text-blue-700">{finalScore}/100</span>
              </p>
              <p className="mt-1 text-xs leading-5 text-slate-500">
                Only evidence-backed non-compliant conditions are included in the deduction.
              </p>
            </div>
          </div>

          <div className="mt-5 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <button type="button" onClick={onClose} className="rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-bold text-slate-700 transition hover:border-blue-200 hover:bg-blue-50 hover:text-blue-700">
              Close
            </button>
            <button type="button" onClick={onViewFindings} className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-bold text-white shadow-lg shadow-blue-200 transition hover:bg-blue-700">
              View detailed findings
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

function Dashboard() {
  const navigate = useNavigate();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [scoreAnalysisOpen, setScoreAnalysisOpen] = useState(false);

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
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-blue-50 text-blue-600">
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

  const handleDownloadFullReport = async () => {
    try {
      await downloadAnalysisJson(effectiveId);
    } catch (err) {
      console.error('Failed to download full report:', err);
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          'The full report could not be downloaded.'
      );
    }
  };

  const handleDownloadPdf = async () => {
    try {
      await downloadAnalysisPdf(effectiveId);
    } catch (err) {
      console.error('Failed to download PDF report:', err);
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          'The PDF report could not be downloaded.'
      );
    }
  };

  if (!effectiveId) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-white p-6">
        <Card className="w-full max-w-lg p-10 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-50 text-blue-600">
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
            className="mt-7 inline-flex items-center gap-2 rounded-full bg-blue-600 px-6 py-3 text-sm font-bold text-white shadow-lg shadow-blue-200 transition hover:bg-blue-700"
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
    <div className="dashboard-page relative min-h-full overflow-hidden bg-gradient-to-br from-white via-blue-50/30 to-slate-50 px-4 py-5 sm:px-6 lg:px-8">
      <div className="pointer-events-none absolute -left-32 top-16 h-96 w-96 rounded-full bg-blue-200/25 blur-3xl" />
      <div className="pointer-events-none absolute left-1/2 top-0 h-64 w-64 -translate-x-1/2 rounded-full bg-cyan-100/30 blur-3xl" />
      <div className="pointer-events-none absolute -right-40 bottom-10 h-96 w-96 rounded-full bg-cyan-200/20 blur-3xl" />

      <div className="relative mx-auto max-w-[1280px] space-y-6">
        {/* Dashboard header */}
        <header className="flex flex-col gap-5 border-b border-blue-100/80 pb-6 lg:flex-row lg:items-end lg:justify-between">
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
              className="inline-flex items-center gap-2 rounded-2xl border border-blue-200 bg-white px-4 py-3 text-sm font-bold text-blue-700 shadow-[0_10px_30px_rgba(37,99,235,0.10)] transition hover:border-blue-300 hover:bg-blue-50 hover:-translate-y-0.5"
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
              tone={postureScore === null ? 'slate' : 'blue'}
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
              tone={riskClass ? 'blue' : 'slate'}
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
        <Card className="overflow-hidden ring-1 ring-blue-100/70 shadow-[0_25px_80px_rgba(15,76,160,0.10)]">
          <div className="grid lg:grid-cols-[1.1fr_1.9fr]">
            <div className="relative overflow-hidden bg-gradient-to-br from-[#061A3A] via-[#0B4EA2] to-[#087EA4] p-7 text-white sm:p-8">
              <div className="pointer-events-none absolute -right-20 -top-20 h-56 w-56 rounded-full bg-cyan-300/15 blur-3xl" />
              <div className="pointer-events-none absolute right-20 bottom-0 h-32 w-32 rounded-full bg-blue-400/10 blur-2xl" />
              <div className="pointer-events-none absolute -bottom-20 -left-10 h-48 w-48 rounded-full bg-cyan-300/15 blur-3xl" />

              <div className="relative">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-blue-200">
                      Cryptographic posture
                    </p>
                    <p className="mt-1 text-sm font-medium text-blue-100">
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
                    <div className="flex h-[106px] w-[106px] flex-col items-center justify-center rounded-full bg-[#04183D] shadow-inner">
                      {postureScore === null ? (
                        <span className="px-3 text-center text-sm font-black leading-tight">
                          Not Assessed
                        </span>
                      ) : (
                        <>
                          <span className="text-3xl font-black tracking-tight">
                            {postureScore}
                          </span>
                          <span className="text-[10px] font-semibold uppercase tracking-wider text-blue-200">
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
                    <p className="mt-3 text-sm leading-6 text-blue-100">
                      {scoreMessage}
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => setScoreAnalysisOpen(true)}
                  disabled={postureScore === null}
                  className="mt-7 inline-flex items-center gap-2 rounded-xl bg-white px-4 py-2.5 text-sm font-extrabold text-[#061A3A] shadow-[0_10px_30px_rgba(0,0,0,0.18)] transition-all duration-200 hover:-translate-y-0.5 hover:bg-blue-50 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <BarChart3 className="h-4 w-4" />
                  How is this score calculated?
                  <ArrowRight className="h-4 w-4" />
                </button>
                <p className="mt-2 text-xs text-blue-100/80">
                  See every issue that added or removed points.
                </p>
              </div>
            </div>

            <div className="p-7 sm:p-8">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-blue-600">
                    Capture intelligence
                  </p>
                  <h2 className="mt-1 text-xl font-black tracking-tight text-slate-900">
                    What the analysis found
                  </h2>
                </div>
                <Sparkles className="h-5 w-5 text-blue-400" />
              </div>

              <div className="mt-6 grid grid-cols-2 gap-3">
                <div className="rounded-2xl border border-blue-100/70 bg-gradient-to-br from-slate-50 to-blue-50/55 p-4">
                  <div className="flex items-center gap-2 text-blue-600">
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

                <div className="rounded-2xl border border-blue-100/70 bg-gradient-to-br from-slate-50 to-blue-50/55 p-4">
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

                <div className="rounded-2xl border border-blue-100/70 bg-gradient-to-br from-slate-50 to-blue-50/55 p-4">
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

                <div className="rounded-2xl border border-blue-100/70 bg-gradient-to-br from-slate-50 to-blue-50/55 p-4">
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

            <Card className="group flex h-full flex-col p-6 transition-all duration-300 hover:-translate-y-1.5 hover:shadow-[0_28px_80px_rgba(15,76,160,0.18)]">
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-blue-100 bg-blue-50 text-blue-600 transition-transform duration-300 group-hover:scale-110">
                <FileText className="h-5 w-5" />
              </div>

              <h3 className="mt-5 text-lg font-black tracking-tight text-slate-900">
                Forensic Report
              </h3>

              <p className="mt-2 min-h-[42px] text-sm leading-6 text-slate-500">
                {reportCardDescription}
              </p>

              <div className="mt-6 grid grid-cols-1 gap-2 sm:grid-cols-2">
                <button
                  type="button"
                  onClick={() => navigate('/reports')}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-blue-600 px-4 py-3 text-sm font-bold text-white shadow-lg shadow-blue-200 transition-all duration-200 hover:-translate-y-0.5 hover:bg-blue-700 active:scale-[0.98]"
                >
                  <FileText className="h-4 w-4" />
                  View Full Report
                </button>

                <button
                  type="button"
                  onClick={handleDownloadPdf}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 text-sm font-bold text-blue-700 transition-all duration-200 hover:-translate-y-0.5 hover:bg-blue-100 active:scale-[0.98]"
                >
                  <Download className="h-4 w-4" />
                  Download Forensic Report
                </button>
              </div>
            </Card>
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

      {scoreAnalysisOpen && (
        <ScoreAnalysisModal
          postureReport={report?.posture_report}
          onClose={() => setScoreAnalysisOpen(false)}
          onViewFindings={() => {
            setScoreAnalysisOpen(false);
            navigate('/findings');
          }}
        />
      )}

      <style>{`
        @keyframes dashboardModalIn {
          from { opacity: 0; transform: translateY(10px) scale(0.985); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }

        .dashboard-modal-enter {
          animation: dashboardModalIn 220ms ease-out both;
        }

        @keyframes dashboardFadeUp {
          from { opacity: 0; transform: translateY(18px); }
          to { opacity: 1; transform: translateY(0); }
        }

        .dashboard-page > div {
          animation: dashboardFadeUp 0.55s ease-out both;
        }

        .dashboard-page > div > header {
          animation: dashboardFadeUp 0.55s ease-out 0.05s both;
        }

        .dashboard-page > div > section:nth-of-type(1) {
          animation: dashboardFadeUp 0.55s ease-out 0.12s both;
        }

        .dashboard-page > div > .overflow-hidden {
          animation: dashboardFadeUp 0.55s ease-out 0.19s both;
        }

        .dashboard-page > div > section:nth-of-type(2) {
          animation: dashboardFadeUp 0.55s ease-out 0.26s both;
        }

        .dashboard-page > div > .p-5 {
          animation: dashboardFadeUp 0.55s ease-out 0.33s both;
        }

        @media (prefers-reduced-motion: reduce) {
          .dashboard-modal-enter,
          .dashboard-page > div,
          .dashboard-page > div > header,
          .dashboard-page > div > section,
          .dashboard-page > div > .overflow-hidden,
          .dashboard-page > div > .p-5 {
            animation: none !important;
          }
        }
      `}</style>
    </div>
  );
}

export default Dashboard;
