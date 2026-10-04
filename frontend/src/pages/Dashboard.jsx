import React, { useEffect, useState, useMemo } from 'react';
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
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import { useAnalysis } from '../hooks/useAnalysis';
import { downloadAnalysisPdf } from '../services/api';
import { SEVERITY_COLORS, STATUS_COLORS } from '../utils/severity';
import {
  isReportApplicable,
  getPostureScore,
  getAssessmentStatus,
  getApplicabilityReason,
  getReportAnalytics,
  CANONICAL_RULES_COUNT,
} from '../utils/reportModel';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { LoadingState } from '../components/LoadingScreen';

// Lightweight count-up hook for smooth numeric reveals
function useCountUp(endValue, duration = 650) {
  const [count, setCount] = useState(0);
  const target = typeof endValue === 'number' && !isNaN(endValue) ? endValue : 0;

  useEffect(() => {
    let startTimestamp = null;
    let frameId;
    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      const eased = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      setCount(Math.round(eased * target));
      if (progress < 1) {
        frameId = requestAnimationFrame(step);
      }
    };
    frameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameId);
  }, [target, duration]);

  return count;
}

const Card = ({ children, className = '', onClick }) => (
  <div
    onClick={onClick}
    className={[
      'rounded-xl border border-[#E5E5E0] bg-white shadow-sm transition-all duration-200',
      onClick ? 'cursor-pointer hover:border-[#D0D0CA] hover:shadow-md' : '',
      className,
    ].join(' ')}
  >
    {children}
  </div>
);

const SectionEyebrow = ({ children }) => (
  <div className="mb-1.5 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-neutral-500">
    <span className="h-1.5 w-1.5 rounded-full bg-[#111111]" />
    {children}
  </div>
);

const OverviewCard = ({ icon: Icon, label, value, detail, tone = 'charcoal', action, microVisual }) => {
  const tones = {
    charcoal: 'bg-[#111111] text-white',
    amber: 'bg-amber-100 text-amber-900 border border-amber-300',
    emerald: 'bg-emerald-100 text-emerald-900 border border-emerald-300',
    rose: 'bg-rose-100 text-rose-900 border border-rose-300',
    slate: 'bg-neutral-100 text-neutral-700 border border-neutral-300',
  };

  return (
    <div className="rounded-xl border border-[#E5E5E0] bg-white p-4 transition-all duration-200 hover:border-[#D0D0CA] hover:shadow-sm flex flex-col justify-between">
      <div>
        <div className="flex items-start justify-between gap-3">
          <div className={`flex h-8 w-8 items-center justify-center rounded-lg ${tones[tone] || tones.charcoal}`}>
            <Icon className="h-4 w-4" />
          </div>
          {action}
        </div>
        <p className="mt-3 text-[10px] font-bold uppercase tracking-[0.14em] text-neutral-400">
          {label}
        </p>
        <p className="mt-0.5 truncate text-xl font-black tracking-tight text-[#111111] font-mono">
          {value}
        </p>
        <p className="mt-0.5 truncate text-xs text-[#666666]">{detail}</p>
      </div>
      {microVisual && (
        <div className="mt-3.5 pt-2.5 border-t border-[#F0F0EB]">
          {microVisual}
        </div>
      )}
    </div>
  );
};

const ActionCard = ({ icon: Icon, title, description, buttonLabel, onClick }) => {
  return (
    <Card className="flex h-full flex-col p-5 hover:border-[#C8C8C0]">
      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#F7F7F5] border border-[#E5E5E0] text-[#111111]">
        <Icon className="h-4.5 w-4.5" />
      </div>
      <h3 className="mt-4 text-base font-bold tracking-tight text-[#111111]">
        {title}
      </h3>
      <p className="mt-1.5 min-h-[38px] text-xs leading-relaxed text-[#666666]">
        {description}
      </p>
      <div className="mt-5 pt-3 border-t border-[#E5E5E0]">
        <button
          type="button"
          onClick={onClick}
          className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-[#111111] px-4 py-2.5 text-xs font-bold uppercase tracking-wider text-white shadow-sm transition hover:bg-[#222222] active:scale-[0.98]"
        >
          {buttonLabel}
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </Card>
  );
};

// Modal explaining the deterministic 100-point budget deductions
const ScoreAnalysisModal = ({ postureReport, onClose, onViewFindings }) => {
  const deductions = postureReport?.applied_deductions || [];
  const baseScore = postureReport?.base_score ?? 100;
  const totalPenalty = postureReport?.total_penalty ?? 0;
  const finalScore = postureReport?.score ?? null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="relative max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-[#E5E5E0] bg-white p-6 sm:p-7 shadow-xl">
        <div className="flex items-start justify-between border-b border-[#E5E5E0] pb-4">
          <div>
            <h3 className="text-lg font-bold text-[#111111]">
              Deterministic Posture Score Calculation
            </h3>
            <p className="mt-1 text-xs text-[#666666]">
              Calibrated 100-point budget evaluated across 19 RFC compliance rules.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-neutral-400 hover:bg-[#F7F7F5] hover:text-[#111111]"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="mt-5 space-y-3">
          <div className="rounded-xl border border-[#E5E5E0] bg-[#F7F7F5] p-4 flex items-center justify-between font-mono text-xs">
            <div>
              <span className="text-neutral-500 font-bold uppercase">Starting Budget:</span>{' '}
              <span className="font-black text-[#111111]">{baseScore} pts</span>
            </div>
            <div>
              <span className="text-rose-600 font-bold uppercase">Total Deductions:</span>{' '}
              <span className="font-black text-rose-600">−{totalPenalty} pts</span>
            </div>
            <div>
              <span className="text-neutral-500 font-bold uppercase">Final Posture:</span>{' '}
              <span className="font-black text-[#111111]">{finalScore}/100</span>
            </div>
          </div>

          <div className="mt-4">
            <h4 className="text-xs font-bold uppercase tracking-wider text-neutral-500 mb-2">
              Verified Deductions ({deductions.length})
            </h4>
            {deductions.length === 0 ? (
              <div className="rounded-lg border border-[#E5E5E0] p-4 text-center text-xs text-neutral-500">
                No penalty deductions applied. Perfect 100/100 baseline.
              </div>
            ) : (
              <div className="space-y-2">
                {deductions.map((ded, idx) => (
                  <div
                    key={ded.rule_id || idx}
                    className="flex items-start justify-between rounded-xl border border-[#E5E5E0] bg-white p-3.5"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-[#111111]">
                          {ded.rule_id}
                        </span>
                        <span className="rounded bg-rose-50 border border-rose-200 px-1.5 py-0.5 text-[10px] font-bold text-rose-700">
                          {ded.rule_severity || 'HIGH'}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-[#666666]">
                        {ded.title || 'Non-compliant security condition'}
                      </p>
                    </div>
                    <span className="font-mono text-xs font-black text-rose-600 shrink-0">
                      −{ded.penalty} pts
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="mt-6 flex items-center justify-end gap-3 border-t border-[#E5E5E0] pt-4">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-[#E5E5E0] bg-white px-4 py-2 text-xs font-bold text-[#111111] hover:bg-[#F7F7F5]"
          >
            Close
          </button>
          <button
            type="button"
            onClick={onViewFindings}
            className="rounded-lg bg-[#111111] px-4 py-2 text-xs font-bold text-white hover:bg-[#222222]"
          >
            Inspect Findings
          </button>
        </div>
      </div>
    </div>
  );
};

const CustomSeverityTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="rounded-lg border border-[#282828] bg-[#111111] px-3 py-2 text-xs text-white shadow-xl select-none">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: data.color }} />
          <span className="font-semibold text-neutral-200">{data.label} Severity</span>
        </div>
        <div className="mt-1 font-mono text-[13px] font-bold text-white">
          {data.count} {data.count === 1 ? 'finding' : 'findings'}
        </div>
      </div>
    );
  }
  return null;
};

export default function Dashboard() {
  const navigate = useNavigate();
  const { report, loading, error, reload, analysisId, processingStatus } = useAnalysis();
  const [scoreAnalysisOpen, setScoreAnalysisOpen] = useState(false);
  const [exportError, setExportError] = useState(null);

  const effectiveId = analysisId || (typeof window !== 'undefined' ? (localStorage.getItem('active_analysis_id') || localStorage.getItem('analysis_id')) : null);

  const isApplicable = isReportApplicable(report);
  const assessmentStatus = getAssessmentStatus(report);
  const applicabilityReason =
    getApplicabilityReason(report) ||
    'No supported email protocol/security assessment was observed in this capture.';

  const rawPostureScore = getPostureScore(report);
  const animatedScore = useCountUp(rawPostureScore, 650);

  const analytics = useMemo(() => getReportAnalytics(report), [report]);
  const findings = useMemo(() => {
    return report?.compliance_findings || report?.findings || [];
  }, [report]);

  const severityCounts = analytics.severityCounts;
  const severityData = analytics.severityData;
  const statusData = analytics.statusData;
  const categoryData = analytics.categoryData;
  const seriousIssues = severityCounts.CRITICAL + severityCounts.HIGH;

  const deductionData = useMemo(() => {
    const applied = report?.posture_report?.applied_deductions || report?.posture_report?.deductions || [];
    return applied.map((d) => ({
      name: d.rule_id || d.upstream_rule_id || 'Rule',
      title: d.title || 'Security Deduction',
      penalty: d.penalty || 0,
    }));
  }, [report]);

  const handleDownloadPdf = async () => {
    if (!effectiveId) return;
    try {
      setExportError(null);
      await downloadAnalysisPdf(effectiveId);
    } catch (err) {
      console.error('Failed to download PDF report:', err);
      setExportError(
        err?.response?.data?.detail || err?.message || 'The PDF report could not be downloaded.'
      );
    }
  };

  // Loading state
  if (loading && !report) {
    return (
      <LoadingState
        title={processingStatus || 'Analyzing Network Capture...'}
        message="Evaluating TCP streams, TLS handshakes, PKI certificates, and deterministic RFC compliance baselines."
      />
    );
  }

  // Graceful No-Capture State
  if (!effectiveId || !report) {
    return (
      <EmptyAnalysisState
        title="START ANALYSIS"
        description="Upload a PCAP to begin email security analysis."
        buttonText="Start Analysis"
        supportingText="Mail Rakhwala will reconstruct email streams, audit TLS/PKI, evaluate security rules, and generate evidence-linked intelligence."
        featureBadge="Dashboard Telemetry"
      />
    );
  }

  // Error State
  if (error) {
    return (
      <div className="flex min-h-[70vh] items-center justify-center bg-[#F7F7F5] p-6">
        <div className="w-full max-w-lg rounded-2xl border border-red-200 bg-white p-8 text-center shadow-sm">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-red-50 text-red-600 mb-4">
            <AlertTriangle className="h-6 w-6" />
          </div>
          <h2 className="text-lg font-bold text-[#111111]">Report Unavailable</h2>
          <p className="mt-2 text-xs text-[#666666]">{error}</p>
          <div className="mt-6 flex items-center justify-center gap-3">
            <button
              type="button"
              onClick={() => reload()}
              className="rounded-lg bg-[#111111] px-4 py-2 text-xs font-bold text-white hover:bg-[#222222]"
            >
              Retry
            </button>
            <button
              type="button"
              onClick={() => navigate('/')}
              className="rounded-lg border border-[#E5E5E0] bg-white px-4 py-2 text-xs font-bold text-[#111111] hover:bg-[#F7F7F5]"
            >
              Upload PCAP
            </button>
          </div>
        </div>
      </div>
    );
  }

  const totalStreams = report?.session?.total_streams ?? 0;
  const detectedProtocol = report?.protocol_summary?.detected_protocol || 'Not detected';
  const riskClass = report?.risk_classification?.predicted_class || null;
  const anomalyValue = typeof report?.anomaly_detection?.is_anomalous === 'boolean'
    ? report.anomaly_detection.is_anomalous
    : null;

  const filename = report?.session?.filename || 'Capture file';
  const fileSizeBytes = report?.session?.filesize_bytes;
  const fileSize = typeof fileSizeBytes === 'number' ? `${(fileSizeBytes / 1024).toFixed(1)} KB` : 'N/A';
  const standardChecked = report?.posture_report?.engine_version
    ? `RFC Conformance v${report.posture_report.engine_version}`
    : 'RFC 8314 / RFC 3207';

  const postureSeverity = report?.posture_report?.severity || 'HIGH';
  const scoreRingPercent = rawPostureScore === null ? 0 : Math.max(0, Math.min(100, rawPostureScore));

  const severityStrokeColor =
    postureSeverity === 'CRITICAL'
      ? '#DC2626'
      : postureSeverity === 'HIGH'
      ? '#EA580C'
      : postureSeverity === 'MEDIUM'
      ? '#D97706'
      : '#16A34A';

  const scoreStatus = !isApplicable
    ? 'Assessment Not Applicable'
    : rawPostureScore === null
    ? 'Not Assessed'
    : rawPostureScore >= 80
    ? 'Strong Posture'
    : rawPostureScore >= 60
    ? 'Needs Attention'
    : 'Review Required';

  return (
    <div className="relative min-h-screen bg-[#F7F7F5] px-4 py-6 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1240px] space-y-6">
        {/* Header */}
        <header className="flex flex-col gap-4 border-b border-[#E5E5E0] pb-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <SectionEyebrow>Passive Email Forensic Console</SectionEyebrow>
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-[#111111]">
                Security Overview
              </h1>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-emerald-800">
                <CheckCircle2 className="h-3 w-3" />
                Analysis Complete
              </span>
            </div>
            <p className="mt-1 text-xs text-[#666666]">
              Deterministic RFC verification, verified deductions, and calibrated cryptographic intelligence.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="rounded-lg border border-[#E5E5E0] bg-white px-3.5 py-2 shadow-sm">
              <p className="text-[9px] font-bold uppercase tracking-wider text-neutral-400">Capture File</p>
              <p className="mt-0.5 max-w-[220px] truncate text-xs font-bold text-[#111111]">{filename}</p>
            </div>
            <button
              type="button"
              onClick={() => navigate('/')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[#111111] px-3.5 py-2 text-xs font-bold uppercase tracking-wider text-white shadow-sm hover:bg-[#222222] transition"
            >
              <Upload className="h-3.5 w-3.5" />
              New Capture
            </button>
          </div>
        </header>

        {/* Non-Applicable Alert */}
        {!isApplicable && (
          <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-700 shrink-0 mt-0.5" />
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-amber-900">Assessment Not Applicable</h3>
              <p className="mt-0.5 text-xs text-amber-800 leading-relaxed">{applicabilityReason}</p>
            </div>
          </div>
        )}

        {/* Overview KPIs with Analytical Micro-Visuals */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
          <OverviewCard
            icon={ShieldCheck}
            label="Cryptographic Posture"
            value={!isApplicable ? 'N/A' : rawPostureScore === null ? 'Not Assessed' : `${animatedScore}/100`}
            detail={!isApplicable ? 'Not Applicable' : `${scoreStatus} · ${postureSeverity}`}
            tone={!isApplicable ? 'slate' : rawPostureScore >= 80 ? 'emerald' : rawPostureScore >= 60 ? 'amber' : 'rose'}
            microVisual={
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10px] font-mono text-neutral-400">
                  <span>Score Budget</span>
                  <span className="font-bold text-[#111111]">{animatedScore}/100</span>
                </div>
                <div className="h-1.5 w-full bg-[#E5E5E0] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${Math.max(0, Math.min(100, rawPostureScore ?? 0))}%`,
                      backgroundColor: severityStrokeColor,
                    }}
                  />
                </div>
              </div>
            }
          />
          <OverviewCard
            icon={AlertTriangle}
            label="Finding Instances"
            value={`${analytics.totalFindings} Finding Instances`}
            detail={`${analytics.uniqueViolatedRulesCount} Unique Violated Rules`}
            tone={seriousIssues > 0 ? 'amber' : 'emerald'}
            microVisual={
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10px] font-mono text-neutral-400">
                  <span>Severity Spread</span>
                  <span className="font-bold text-[#111111]">{analytics.totalFindings} findings</span>
                </div>
                <div className="flex h-1.5 w-full gap-0.5 rounded-full overflow-hidden bg-[#F0F0EB]">
                  <div style={{ flex: severityCounts.CRITICAL || 0.05 }} className="bg-[#DC2626] rounded-xs" title={`Critical: ${severityCounts.CRITICAL}`} />
                  <div style={{ flex: severityCounts.HIGH || 0.05 }} className="bg-[#EA580C] rounded-xs" title={`High: ${severityCounts.HIGH}`} />
                  <div style={{ flex: severityCounts.MEDIUM || 0.05 }} className="bg-[#D97706] rounded-xs" title={`Medium: ${severityCounts.MEDIUM}`} />
                  <div style={{ flex: severityCounts.LOW || 0.05 }} className="bg-[#16A34A] rounded-xs" title={`Low: ${severityCounts.LOW}`} />
                  {severityCounts.INFORMATIONAL > 0 && (
                    <div style={{ flex: severityCounts.INFORMATIONAL }} className="bg-[#64748B] rounded-xs" title={`Informational: ${severityCounts.INFORMATIONAL}`} />
                  )}
                </div>
              </div>
            }
          />
          <OverviewCard
            icon={Activity}
            label="Statistical Risk (ML)"
            value={!isApplicable ? 'N/A' : (riskClass || 'Evaluated')}
            detail={!isApplicable ? 'Not Applicable' : anomalyValue ? 'Anomaly Flagged' : 'Normal Pattern'}
            tone={riskClass === 'CRITICAL' ? 'rose' : riskClass === 'HIGH' ? 'amber' : 'slate'}
            microVisual={
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10px] font-mono text-neutral-400">
                  <span>Model Output</span>
                  <span className="font-bold text-[#111111]">{riskClass || 'EVAL'}</span>
                </div>
                <div className="grid grid-cols-4 gap-1">
                  {['LOW', 'MED', 'HIGH', 'CRIT'].map((lvl, idx) => {
                    const fullLvl = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][idx];
                    const isActive = (riskClass || '').toUpperCase() === fullLvl;
                    return (
                      <div
                        key={lvl}
                        className={`text-center py-0.5 text-[8px] font-mono font-bold rounded ${
                          isActive
                            ? 'bg-[#111111] text-white'
                            : 'bg-[#F0F0EB] text-neutral-400'
                        }`}
                      >
                        {lvl}
                      </div>
                    );
                  })}
                </div>
              </div>
            }
          />
          <OverviewCard
            icon={Mail}
            label="Stream Dissection"
            value={`${totalStreams} Streams`}
            detail={`${detectedProtocol} · ${fileSize}`}
            tone="charcoal"
            microVisual={
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10px] font-mono text-neutral-400">
                  <span>Reassembly</span>
                  <span className="font-bold text-emerald-700">Active</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="text-[10px] font-mono font-bold text-[#111111]">{detectedProtocol}</span>
                  <span className="text-[10px] text-neutral-400 ml-auto font-mono">{fileSize}</span>
                </div>
              </div>
            }
          />
        </section>

        {/* CENTERPIECE: Cryptographic Posture Card (Dark Charcoal #111111) */}
        <div className="overflow-hidden rounded-2xl border border-[#222222] bg-[#111111] text-white shadow-md">
          <div className="grid lg:grid-cols-[1.1fr_1.9fr]">
            {/* Left Score Centerpiece */}
            <div className="relative p-6 sm:p-8 border-b lg:border-b-0 lg:border-r border-[#222222] technical-grid-pattern">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-neutral-400">
                    Authoritative Security Engine
                  </p>
                  <h2 className="mt-1 text-base font-bold text-white">
                    Cryptographic Posture
                  </h2>
                </div>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[#222222] text-neutral-300">
                  <LockKeyhole className="h-4 w-4" />
                </div>
              </div>

              {/* Score Ring */}
              <div className="mt-7 flex items-center gap-6">
                <div className="relative flex h-28 w-28 shrink-0 items-center justify-center">
                  <svg className="h-full w-full -rotate-90" viewBox="0 0 100 100">
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      fill="transparent"
                      stroke="#222222"
                      strokeWidth="8"
                    />
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      fill="transparent"
                      stroke={severityStrokeColor}
                      strokeWidth="8"
                      strokeDasharray={2 * Math.PI * 40}
                      strokeDashoffset={2 * Math.PI * 40 * (1 - scoreRingPercent / 100)}
                      strokeLinecap="round"
                      className="transition-all duration-700 ease-out"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-3xl font-black tracking-tight text-white font-mono">
                      {animatedScore}
                    </span>
                    <span className="text-[9px] font-bold uppercase tracking-wider text-neutral-400">
                      / 100
                    </span>
                  </div>
                </div>

                <div className="min-w-0">
                  <span
                    className="inline-flex rounded-md px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider font-mono"
                    style={{
                      backgroundColor: `${severityStrokeColor}20`,
                      color: severityStrokeColor,
                      border: `1px solid ${severityStrokeColor}40`,
                    }}
                  >
                    {postureSeverity} RISK
                  </span>
                  <p className="mt-2 text-xs text-neutral-300 leading-relaxed">
                    {scoreStatus} evaluated against deterministic RFC rules.
                  </p>
                </div>
              </div>

              <div className="mt-6 pt-5 border-t border-[#222222] flex flex-col gap-2">
                <button
                  type="button"
                  onClick={() => setScoreAnalysisOpen(true)}
                  disabled={rawPostureScore === null || !isApplicable}
                  className="inline-flex items-center justify-between rounded-lg bg-white px-4 py-2 text-xs font-bold text-[#111111] hover:bg-[#EAEAEA] transition"
                >
                  <span className="flex items-center gap-2">
                    <BarChart3 className="h-3.5 w-3.5" />
                    How is this score calculated?
                  </span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
                <p className="text-[10px] text-neutral-400">
                  Base score 100 minus verified deductions across 19 rules.
                </p>
              </div>
            </div>

            {/* Right Side: What the Analysis Found */}
            <div className="p-6 sm:p-8 bg-[#161616] flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-5">
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-neutral-400">
                      Capture Telemetry
                    </p>
                    <h3 className="mt-0.5 text-sm font-bold text-white">
                      Verified Findings &amp; Protocol Boundaries
                    </h3>
                  </div>
                  <Sparkles className="h-4 w-4 text-neutral-400" />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-xl border border-[#252525] bg-[#1E1E1E] p-3.5">
                    <div className="flex items-center gap-2 text-neutral-400 text-[10px] font-bold uppercase tracking-wider">
                      <Network className="h-3.5 w-3.5" />
                      Reconstructed Streams
                    </div>
                    <p className="mt-2 text-2xl font-black text-white font-mono">{totalStreams}</p>
                    <p className="text-[10px] text-neutral-400">TCP stream handshakes</p>
                  </div>

                  <div className="rounded-xl border border-[#252525] bg-[#1E1E1E] p-3.5">
                    <div className="flex items-center gap-2 text-neutral-400 text-[10px] font-bold uppercase tracking-wider">
                      <AlertTriangle className="h-3.5 w-3.5" />
                      Finding Instances
                    </div>
                    <p className="mt-2 text-2xl font-black text-white font-mono">{analytics.totalFindings}</p>
                    <p className="text-[10px] text-neutral-400">{analytics.uniqueViolatedRulesCount} Unique Violated Rules</p>
                  </div>

                  <div className="rounded-xl border border-[#252525] bg-[#1E1E1E] p-3.5">
                    <div className="flex items-center gap-2 text-neutral-400 text-[10px] font-bold uppercase tracking-wider">
                      <Mail className="h-3.5 w-3.5" />
                      Protocol Baseline
                    </div>
                    <p className="mt-2 text-base font-bold text-white truncate">{detectedProtocol}</p>
                    <p className="text-[10px] text-neutral-400">Port-identified service</p>
                  </div>

                  <div className="rounded-xl border border-[#252525] bg-[#1E1E1E] p-3.5">
                    <div className="flex items-center gap-2 text-neutral-400 text-[10px] font-bold uppercase tracking-wider">
                      <Layers3 className="h-3.5 w-3.5" />
                      Audit Standard
                    </div>
                    <p className="mt-2 text-xs font-bold text-white truncate">{standardChecked}</p>
                    <p className="text-[10px] text-neutral-400">19 Canonical Rules in Scope</p>
                  </div>
                </div>
              </div>

              <div className="mt-5 pt-4 border-t border-[#252525] flex items-center justify-between text-xs text-neutral-400">
                <span>Total verified deductions: <strong className="text-white font-mono">−{analytics.totalPenalty} pts</strong></span>
                <span className="font-mono text-[11px] text-neutral-500">Hash: {effectiveId.slice(0, 12)}...</span>
              </div>
            </div>
          </div>
        </div>

        {/* Upgraded Analytics Visualization Grid (Requirement 11) */}
        <section className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-bold uppercase tracking-wider text-[#111111]">
                Compliance &amp; Severity Analytics
              </h2>
              <p className="text-xs text-[#666666]">
                Evidence-backed distribution across severity levels, RFC compliance baselines, and functional domains. Finding instances are evidence-backed occurrences produced by the canonical rule engine; one rule may produce multiple instances across streams.
              </p>
            </div>
            <span className="text-[11px] font-mono font-bold text-neutral-600 bg-white border border-[#E5E5E0] px-2.5 py-1 rounded-lg shadow-sm self-start sm:self-auto">
              19 Canonical Rules in Scope
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Card 1: Findings by Severity - Restored Bar Chart with Real Data */}
            <Card className="p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3.5 pb-2.5 border-b border-[#E5E5E0]">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[#111111] flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-neutral-700" />
                    Findings by Severity
                  </h3>
                  <span className="text-[11px] text-neutral-500 font-mono font-bold">{analytics.totalFindings} Finding Instances</span>
                </div>

                <div className="h-44 w-full pt-1">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={severityData}
                      margin={{ top: 12, right: 10, left: -22, bottom: 0 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#EBEBEA" />
                      <XAxis
                        dataKey="label"
                        stroke="#888888"
                        fontSize={11}
                        tickLine={false}
                        axisLine={{ stroke: '#E5E5E0' }}
                      />
                      <YAxis
                        stroke="#888888"
                        fontSize={11}
                        tickLine={false}
                        axisLine={{ stroke: '#E5E5E0' }}
                        allowDecimals={false}
                      />
                      <Tooltip content={<CustomSeverityTooltip />} cursor={{ fill: '#F5F5F0', opacity: 0.6 }} />
                      <Bar
                        dataKey="count"
                        radius={[4, 4, 0, 0]}
                        isAnimationActive={true}
                        animationDuration={600}
                      >
                        {severityData.map((entry, index) => (
                          <Cell key={`sev-cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-[#F0F0EB] flex items-center justify-between text-[11px] text-neutral-500 font-mono">
                <span>Total finding instances: <strong className="text-[#111111]">{analytics.totalFindings}</strong></span>
                <span>Critical + High: <strong className={seriousIssues > 0 ? 'text-rose-600' : 'text-emerald-700'}>{seriousIssues}</strong></span>
              </div>
            </Card>

            {/* Card 2: Compliance Status Donut (Requirement 11.B - Center Total & Percentages) */}
            <Card className="p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3.5 pb-2.5 border-b border-[#E5E5E0]">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[#111111] flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-neutral-700" />
                    Compliance Status
                  </h3>
                  <span className="text-[11px] text-neutral-500 font-mono font-bold">RFC Conformance</span>
                </div>

                <div className="relative h-44 w-full flex items-center justify-center">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={statusData.filter((d) => d.count > 0)}
                        dataKey="count"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={70}
                        paddingAngle={3}
                      >
                        {statusData.filter((d) => d.count > 0).map((entry, index) => (
                          <Cell key={`st-cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#111111',
                          borderColor: '#222222',
                          borderRadius: '8px',
                          color: '#FFFFFF',
                          fontSize: '11px',
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>

                  {/* Donut Centerpiece Total */}
                  <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span className="text-2xl font-black text-[#111111] font-mono leading-none">
                      {analytics.totalFindings}
                    </span>
                    <span className="text-[9px] font-bold uppercase tracking-wider text-neutral-400 mt-1">
                      Total Findings
                    </span>
                  </div>
                </div>
              </div>

              {/* Semantic Donut Legend */}
              <div className="grid grid-cols-2 gap-2 pt-3 border-t border-[#F0F0EB] text-[11px]">
                {statusData.map((item) => (
                  <div key={item.name} className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className="h-2 w-2 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                      <span className="truncate text-neutral-600">{item.shortLabel || item.label}</span>
                    </div>
                    <span className="font-mono font-bold text-[#111111] ml-1">{item.count}</span>
                  </div>
                ))}
              </div>
            </Card>

            {/* Card 3: Issue Categories (Requirement 11.C - Horizontal Ranking Bars) */}
            <Card className="p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3.5 pb-2.5 border-b border-[#E5E5E0]">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[#111111] flex items-center gap-2">
                    <Layers3 className="h-4 w-4 text-neutral-700" />
                    Issue Categories
                  </h3>
                  <span className="text-[11px] text-neutral-500 font-mono font-bold">5 Domains</span>
                </div>

                <div className="space-y-3 pt-1">
                  {categoryData.map((cat) => (
                    <div key={cat.name} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-[#111111] truncate max-w-[170px]" title={cat.name}>
                          {cat.name}
                        </span>
                        <div className="flex items-center gap-1.5 font-mono text-[10px]">
                          {cat.findingsCount > 0 ? (
                            <span className="font-bold text-rose-700 bg-rose-50 border border-rose-200 px-1.5 py-0.5 rounded">
                              {cat.findingsCount} {cat.findingsCount === 1 ? 'finding' : 'findings'} / {cat.evaluatedCount} evaluated
                            </span>
                          ) : (
                            <span className="font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-1.5 py-0.5 rounded">
                              0 findings / {cat.evaluatedCount} evaluated • Passed
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="h-1.5 w-full rounded-full bg-[#F0F0EB] overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${Math.max(cat.evaluatedCount > 0 ? 8 : 0, cat.percent)}%`,
                            backgroundColor: cat.findingsCount > 0 ? '#DC2626' : '#16A34A',
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-5 pt-3 border-t border-[#F0F0EB] text-[11px] text-neutral-500 font-mono flex items-center justify-between">
                <span>Functional domains:</span>
                <span className="font-bold text-[#111111]">{categoryData.length} active domains</span>
              </div>
            </Card>
          </div>

          {/* Penalty Deductions Bar Chart */}
          {deductionData.length > 0 && (
            <Card className="p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[#111111] flex items-center gap-2">
                    <BarChart3 className="h-4 w-4 text-neutral-700" />
                    Penalty Point Deductions by Rule
                  </h3>
                  <p className="text-[11px] text-neutral-500 mt-0.5">
                    Individual penalties subtracted from the 100-point budget baseline.
                  </p>
                </div>
                <span className="font-mono text-xs font-bold text-rose-600 bg-rose-50 border border-rose-200 px-2.5 py-1 rounded">
                  Total Penalty: −{report?.posture_report?.total_penalty ?? 0} pts
                </span>
              </div>

              <div className="h-48 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={deductionData} margin={{ top: 10, right: 20, left: 0, bottom: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#E5E5E0" />
                    <XAxis dataKey="name" stroke="#888888" fontSize={10} />
                    <YAxis stroke="#888888" fontSize={10} unit=" pts" />
                    <Tooltip
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          const item = payload[0].payload;
                          return (
                            <div className="rounded-lg border border-[#222222] bg-[#111111] p-2.5 shadow-md text-white text-xs">
                              <p className="font-bold">{item.name}</p>
                              <p className="text-neutral-400">{item.title}</p>
                              <p className="text-rose-400 font-mono font-bold mt-1">
                                Penalty: −{item.penalty} pts
                              </p>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                    <Bar dataKey="penalty" fill="#111111" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
          )}
        </section>

        {/* Action Cards: Next Steps */}
        <section>
          <div className="mb-3">
            <h2 className="text-sm font-bold uppercase tracking-wider text-[#111111]">
              Continue Investigation
            </h2>
            <p className="text-xs text-[#666666]">
              Deep-dive into reconstructed streams, findings telemetry, or export a court-ready PDF.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <ActionCard
              icon={Network}
              title="Stream Analysis"
              description="Inspect packet boundaries, handshakes, and conversation transcripts for every TCP stream."
              buttonLabel="Inspect Streams"
              onClick={() => navigate('/analysis')}
            />

            <ActionCard
              icon={AlertTriangle}
              title="Findings &amp; CVEs"
              description="Review security non-compliances, penalty points, and verified evidence links."
              buttonLabel="View Findings"
              onClick={() => navigate('/findings')}
            />

            <Card className="flex flex-col p-5 hover:border-[#C8C8C0]">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#F7F7F5] border border-[#E5E5E0] text-[#111111]">
                <FileText className="h-4.5 w-4.5" />
              </div>
              <h3 className="mt-4 text-base font-bold tracking-tight text-[#111111]">
                Forensic Report
              </h3>
              <p className="mt-1.5 min-h-[38px] text-xs leading-relaxed text-[#666666]">
                {filename} · {fileSize} · {totalStreams} stream{totalStreams === 1 ? '' : 's'} inspected.
              </p>
              <div className="mt-5 pt-3 border-t border-[#E5E5E0] grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => navigate('/reports')}
                  className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-[#111111] px-3 py-2 text-xs font-bold uppercase tracking-wider text-white shadow-sm hover:bg-[#222222]"
                >
                  <FileText className="h-3.5 w-3.5" />
                  View Report
                </button>
                <button
                  type="button"
                  onClick={handleDownloadPdf}
                  className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[#E5E5E0] bg-white px-3 py-2 text-xs font-bold text-[#111111] hover:bg-[#F7F7F5]"
                >
                  <Download className="h-3.5 w-3.5" />
                  PDF Export
                </button>
              </div>
            </Card>
          </div>
        </section>
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
    </div>
  );
}
