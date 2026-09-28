import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  FileWarning,
  Filter,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  Upload,
} from 'lucide-react';
import { getActiveAnalysisId, getAnalysisReport } from '../services/api';

const Card = ({ children, className = '' }) => (
  <section
    className={[
      'rounded-3xl border border-blue-100 bg-white',
      'shadow-[0_18px_55px_rgba(15,76,160,0.08)]',
      className,
    ].join(' ')}
  >
    {children}
  </section>
);

const SectionLabel = ({ children }) => (
  <div className="flex items-center gap-2 text-[11px] font-extrabold uppercase tracking-[0.18em] text-[#0B5ED7]">
    <span className="h-1.5 w-1.5 rounded-full bg-[#0B5ED7]" />
    {children}
  </div>
);

const normalize = (value) => String(value ?? '').trim().toUpperCase();

const displayValue = (value) => {
  if (value === null || value === undefined || value === '') {
    return 'Not observed';
  }
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }
  return String(value);
};

const severityClasses = (severity) => {
  switch (normalize(severity)) {
    case 'CRITICAL':
      return 'border-red-100 bg-red-50 text-red-700';
    case 'HIGH':
      return 'border-orange-100 bg-orange-50 text-orange-700';
    case 'MEDIUM':
      return 'border-amber-100 bg-amber-50 text-amber-700';
    case 'LOW':
      return 'border-slate-200 bg-slate-100 text-slate-600';
    default:
      return 'border-blue-100 bg-blue-50 text-[#0B5ED7]';
  }
};

const severityDot = (severity) => {
  switch (normalize(severity)) {
    case 'CRITICAL':
      return 'bg-red-500';
    case 'HIGH':
      return 'bg-orange-500';
    case 'MEDIUM':
      return 'bg-amber-500';
    case 'LOW':
      return 'bg-slate-400';
    default:
      return 'bg-[#0B5ED7]';
  }
};

const statusClasses = (status) => {
  switch (normalize(status)) {
    case 'NON_COMPLIANT':
      return 'border-red-100 bg-red-50 text-red-700';
    case 'UNKNOWN':
      return 'border-amber-100 bg-amber-50 text-amber-700';
    case 'NOT_APPLICABLE':
      return 'border-slate-200 bg-slate-100 text-slate-600';
    default:
      return 'border-emerald-100 bg-emerald-50 text-emerald-700';
  }
};

const getFindingSeverity = (finding) =>
  normalize(finding?.severity || finding?.level || finding?.risk || 'UNKNOWN');

const getFindingTitle = (finding) =>
  finding?.title ||
  finding?.name ||
  finding?.rule_name ||
  finding?.rule_id ||
  'Security finding';

const getFindingDescription = (finding) =>
  finding?.description ||
  finding?.message ||
  finding?.detail ||
  'The analysis pipeline reported this finding.';

const getFindingRuleId = (finding) =>
  finding?.rule_id || finding?.rule || finding?.id || 'Rule ID unavailable';

const getFindingStatus = (finding) =>
  finding?.status || finding?.compliance_status || 'UNKNOWN';

const getFindings = (report) => {
  const source = report?.compliance_findings;
  if (Array.isArray(source)) return source;
  if (Array.isArray(source?.findings)) return source.findings;
  return [];
};

export default function Findings() {
  const navigate = useNavigate();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [expanded, setExpanded] = useState(null);

  const resolveCurrentId = () =>
    getActiveAnalysisId() ||
    localStorage.getItem('active_analysis_id') ||
    localStorage.getItem('analysis_id') ||
    null;

  useEffect(() => {
    let cancelled = false;

    const loadReport = async () => {
      const analysisId = resolveCurrentId();

      if (!analysisId) {
        if (!cancelled) {
          setReport(null);
          setLoading(false);
        }
        return;
      }

      setLoading(true);
      setError(null);

      try {
        const data = await getAnalysisReport(analysisId);
        if (!cancelled) setReport(data);
      } catch (err) {
        console.error('Failed to load findings:', err);
        if (!cancelled) {
          setError(
            err?.response?.data?.detail ||
              'The findings report could not be loaded.'
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    loadReport();

    const handleIdChange = () => loadReport();
    window.addEventListener('analysisIdChanged', handleIdChange);
    window.addEventListener('storage', handleIdChange);

    return () => {
      cancelled = true;
      window.removeEventListener('analysisIdChanged', handleIdChange);
      window.removeEventListener('storage', handleIdChange);
    };
  }, []);

  const findings = useMemo(() => getFindings(report), [report]);

  const counts = useMemo(() => {
    const result = {
      total: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      nonCompliant: 0,
    };

    findings.forEach((finding) => {
      const severity = getFindingSeverity(finding);
      const status = normalize(getFindingStatus(finding));

      if (severity === 'CRITICAL') result.critical += 1;
      if (severity === 'HIGH') result.high += 1;
      if (severity === 'MEDIUM') result.medium += 1;
      if (severity === 'LOW') result.low += 1;
      if (status === 'NON_COMPLIANT') result.nonCompliant += 1;
    });

    return result;
  }, [findings]);

  const filteredFindings = useMemo(
    () =>
      findings.filter((finding) => {
        const severity = getFindingSeverity(finding);
        const status = normalize(getFindingStatus(finding));

        const severityMatches =
          severityFilter === 'ALL' || severity === severityFilter;
        const statusMatches =
          statusFilter === 'ALL' || status === statusFilter;

        return severityMatches && statusMatches;
      }),
    [findings, severityFilter, statusFilter]
  );

  if (loading) {
    return (
      <div className="min-h-screen bg-[#f8fbff] px-6 py-10">
        <div className="mx-auto flex min-h-[70vh] max-w-6xl items-center justify-center">
          <div className="flex flex-col items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-blue-50 text-[#0B5ED7] shadow-sm">
              <ShieldAlert className="h-5 w-5 animate-pulse" />
            </div>
            <p className="text-sm font-semibold text-slate-600">
              Loading security findings...
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="min-h-screen bg-[#f8fbff] px-6 py-10">
        <div className="mx-auto flex min-h-[70vh] max-w-2xl items-center justify-center">
          <Card className="w-full p-10 text-center">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-50 text-[#0B5ED7]">
              <TerminalSquare className="h-7 w-7" />
            </div>
            <h1 className="mt-5 text-2xl font-black tracking-tight text-slate-900">
              No active analysis
            </h1>
            <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">
              Upload a PCAP capture first. Findings will appear here when the
              backend analysis report is available.
            </p>
            <button
              type="button"
              onClick={() => navigate('/')}
              className="mt-6 inline-flex items-center gap-2 rounded-xl bg-[#0B5ED7] px-5 py-3 text-sm font-bold text-white shadow-[0_8px_24px_rgba(11,94,215,0.20)] transition hover:bg-[#084FB8]"
            >
              <Upload className="h-4 w-4" />
              Upload PCAP
            </button>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#f8fbff]">
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -left-[18%] -top-[16%] h-[52vh] w-[50vw] rounded-full bg-blue-300/12 blur-[120px]" />
        <div className="absolute -right-[18%] top-[10%] h-[48vh] w-[48vw] rounded-full bg-cyan-300/10 blur-[120px]" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(255,255,255,0.98)_0%,rgba(255,255,255,0.92)_58%,rgba(248,251,255,0.72)_100%)]" />
      </div>

      <div className="relative z-10 mx-auto max-w-[1400px] px-6 py-8 lg:px-10">
        <div className="mb-8 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <button
              type="button"
              onClick={() => navigate('/analysis')}
              className="mb-5 inline-flex items-center gap-2 text-xs font-bold text-slate-500 transition hover:text-[#0B5ED7]"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to stream analysis
            </button>

            <SectionLabel>Security Findings</SectionLabel>

            <h1 className="mt-2 text-4xl font-black tracking-[-0.04em] text-[#192837]">
              Security Findings
            </h1>

            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
              Review evidence-backed security findings reported by the analysis pipeline for this capture.
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-2 text-[10px] font-semibold text-slate-400">
              <span className="rounded-full border border-blue-100 bg-white px-2.5 py-1">
                {findings.length} finding{findings.length === 1 ? '' : 's'}
              </span>
              {report?.analysis_id && (
                <span className="rounded-full border border-blue-100 bg-blue-50/60 px-2.5 py-1 font-mono text-[#0B5ED7]">
                  {String(report.analysis_id).slice(0, 18)}…
                </span>
              )}
            </div>
          </div>

          <button
            type="button"
            onClick={() => navigate('/')}
            className="inline-flex w-fit items-center gap-2 rounded-2xl border border-blue-200 bg-white px-4 py-3 text-sm font-bold text-[#0B5ED7] transition hover:border-blue-300 hover:bg-blue-50"
          >
            <Upload className="h-4 w-4" />
            New capture
          </button>
        </div>

        {error && (
          <Card className="mb-6 border-red-100">
            <div className="flex items-start gap-4 p-5">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-red-50 text-red-600">
                <CircleAlert className="h-5 w-5" />
              </div>
              <div>
                <p className="font-bold text-slate-900">
                  Could not load findings
                </p>
                <p className="mt-1 text-sm text-slate-500">{error}</p>
              </div>
            </div>
          </Card>
        )}

        <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
          {[
            ['Total', counts.total, 'text-[#0B5ED7]', 'bg-blue-50'],
            ['Critical', counts.critical, 'text-red-700', 'bg-red-50'],
            ['High', counts.high, 'text-orange-700', 'bg-orange-50'],
            ['Medium', counts.medium, 'text-amber-700', 'bg-amber-50'],
            ['Low', counts.low, 'text-slate-700', 'bg-slate-100'],
          ].map(([label, value, text, bg]) => (
            <div
              key={label}
              className="rounded-2xl border border-slate-100 bg-white p-5 shadow-[0_12px_35px_rgba(15,76,160,0.06)]"
            >
              <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${bg} ${text}`}>
                <FileWarning className="h-5 w-5" />
              </div>
              <p className="mt-4 text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
                {label}
              </p>
              <p className="mt-1 text-3xl font-black text-slate-950">
                {value}
              </p>
            </div>
          ))}
        </div>

        <Card className="mt-6 overflow-hidden">
          <div className="flex flex-col gap-4 border-b border-blue-100/80 px-6 py-5 lg:flex-row lg:items-center lg:justify-between sm:px-7">
            <div>
              <SectionLabel>Evidence Review</SectionLabel>
              <h2 className="mt-2 text-xl font-black tracking-tight text-slate-950">
                Reported findings
              </h2>
              <p className="mt-1 text-sm text-slate-500">
                Expand a finding to inspect the evidence fields returned by the backend.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-400">
                <Filter className="h-4 w-4" />
                Filter
              </div>

              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setSeverityFilter(value)}
                  className={[
                    'rounded-xl border px-3 py-2 text-xs font-bold transition',
                    severityFilter === value
                      ? 'border-[#0B5ED7] bg-[#0B5ED7] text-white'
                      : 'border-slate-200 bg-white text-slate-600 hover:border-blue-200 hover:text-[#0B5ED7]',
                  ].join(' ')}
                >
                  {value === 'ALL' ? 'All severity' : value}
                </button>
              ))}

              <select
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value)}
                className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-600 outline-none focus:border-[#0B5ED7]"
              >
                <option value="ALL">All status</option>
                <option value="NON_COMPLIANT">Non-compliant</option>
                <option value="UNKNOWN">Unknown</option>
                <option value="NOT_APPLICABLE">Not applicable</option>
                <option value="COMPLIANT">Compliant</option>
              </select>
            </div>
          </div>

          {filteredFindings.length === 0 ? (
            <div className="px-6 py-14 text-center sm:px-7">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-emerald-50 text-emerald-600">
                <ShieldCheck className="h-7 w-7" />
              </div>
              <h3 className="mt-4 text-lg font-black text-slate-900">
                No findings match these filters
              </h3>
              <p className="mx-auto mt-1 max-w-md text-sm leading-6 text-slate-500">
                No finding records returned by the backend match the selected
                severity and status filters.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {filteredFindings.map((finding, index) => {
                const key =
                  finding?.rule_id ||
                  finding?.id ||
                  `${getFindingTitle(finding)}-${index}`;
                const isOpen = expanded === key;
                const severity = getFindingSeverity(finding);
                const status = getFindingStatus(finding);

                return (
                  <div key={key} className="px-6 py-5 sm:px-7">
                    <button
                      type="button"
                      onClick={() => setExpanded(isOpen ? null : key)}
                      className="w-full text-left"
                    >
                      <div className="flex items-start gap-4">
                        <div className="mt-1 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-blue-50 text-[#0B5ED7]">
                          <AlertTriangle className="h-5 w-5" />
                        </div>

                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-extrabold ${severityClasses(severity)}`}
                            >
                              <span className={`h-1.5 w-1.5 rounded-full ${severityDot(severity)}`} />
                              {severity}
                            </span>

                            <span
                              className={`rounded-full border px-2.5 py-1 text-[10px] font-extrabold ${statusClasses(status)}`}
                            >
                              {normalize(status) || 'UNKNOWN'}
                            </span>

                            <span className="font-mono text-[10px] font-bold text-slate-400">
                              {getFindingRuleId(finding)}
                            </span>
                          </div>

                          <h3 className="mt-2 text-base font-black text-slate-950">
                            {getFindingTitle(finding)}
                          </h3>

                          <p className="mt-1 text-sm leading-6 text-slate-500">
                            {getFindingDescription(finding)}
                          </p>
                        </div>

                        <ChevronDown
                          className={[
                            'mt-2 h-5 w-5 shrink-0 text-slate-400 transition-transform',
                            isOpen ? 'rotate-180 text-[#0B5ED7]' : '',
                          ].join(' ')}
                        />
                      </div>
                    </button>

                    {isOpen && (
                      <div className="ml-14 mt-5 grid grid-cols-1 gap-3 md:grid-cols-2">
                        <div className="rounded-2xl border border-slate-100 bg-slate-50 p-4">
                          <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
                            Observed property
                          </p>
                          <p className="mt-2 break-words text-sm font-bold text-slate-900">
                            {displayValue(finding?.observed_prop)}
                          </p>
                        </div>

                        <div className="rounded-2xl border border-slate-100 bg-slate-50 p-4">
                          <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
                            Observed value
                          </p>
                          <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-xs leading-5 text-slate-800">
                            {displayValue(finding?.observed_val)}
                          </pre>
                        </div>

                        <div className="rounded-2xl border border-slate-100 bg-slate-50 p-4">
                          <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
                            Reference value
                          </p>
                          <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-xs leading-5 text-slate-800">
                            {displayValue(finding?.ref_val)}
                          </pre>
                        </div>

                        <div className="rounded-2xl border border-slate-100 bg-slate-50 p-4">
                          <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
                            Stream / packet evidence
                          </p>
                          <div className="mt-2 space-y-1.5 text-xs text-slate-700">
                            <p>
                              <span className="font-bold text-slate-500">Stream:</span>{' '}
                              {displayValue(finding?.stream_id ?? finding?.stream)}
                            </p>
                            <p>
                              <span className="font-bold text-slate-500">Packet:</span>{' '}
                              {displayValue(finding?.packet ?? finding?.frame)}
                            </p>
                            <p>
                              <span className="font-bold text-slate-500">Timestamp:</span>{' '}
                              {displayValue(finding?.timestamp)}
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        <div className="mt-8 flex justify-center">
          <button
            type="button"
            onClick={() => navigate('/analysis')}
            className="inline-flex items-center gap-2 rounded-xl bg-[#0B5ED7] px-6 py-3 text-sm font-bold text-white shadow-[0_8px_24px_rgba(11,94,215,0.20)] transition hover:bg-[#084FB8] active:scale-[0.98]"
          >
            <ArrowLeft className="h-4 w-4" />
            View Stream Analysis
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
