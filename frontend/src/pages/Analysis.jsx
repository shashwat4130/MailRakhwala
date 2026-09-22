import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ChevronRight,
  CircleAlert,
  Layers3,
  LockKeyhole,
  Mail,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  Upload,
} from 'lucide-react';
import { getActiveAnalysisId, getAnalysisReport } from '../services/api';

const Card = ({ children, className = '' }) => (
  <section
    className={[
      'rounded-3xl border border-violet-100 bg-white',
      'shadow-[0_18px_55px_rgba(71,38,130,0.08)]',
      className,
    ].join(' ')}
  >
    {children}
  </section>
);

const SectionLabel = ({ children }) => (
  <div className="flex items-center gap-2 text-[11px] font-extrabold uppercase tracking-[0.18em] text-violet-600">
    <span className="h-1.5 w-1.5 rounded-full bg-violet-500" />
    {children}
  </div>
);

const valueOrUnavailable = (value) => {
  if (value === null || value === undefined || value === '') {
    return 'Not observed';
  }
  return String(value);
};

const normalizeProtocol = (value) => String(value || '').trim().toUpperCase();

const getFindingSeverity = (finding) =>
  normalizeProtocol(finding?.severity || finding?.level || '');

const severityClasses = (severity) => {
  const value = normalizeProtocol(severity);

  if (value === 'CRITICAL') {
    return 'bg-red-50 text-red-700 border-red-100';
  }
  if (value === 'HIGH') {
    return 'bg-orange-50 text-orange-700 border-orange-100';
  }
  if (value === 'MEDIUM') {
    return 'bg-amber-50 text-amber-700 border-amber-100';
  }
  if (value === 'LOW') {
    return 'bg-slate-100 text-slate-600 border-slate-200';
  }
  return 'bg-emerald-50 text-emerald-700 border-emerald-100';
};

const statusClasses = (status) => {
  const value = normalizeProtocol(status);

  if (value === 'NON_COMPLIANT') {
    return 'bg-red-50 text-red-700 border-red-100';
  }
  if (value === 'UNKNOWN') {
    return 'bg-amber-50 text-amber-700 border-amber-100';
  }
  if (value === 'NOT_APPLICABLE') {
    return 'bg-slate-100 text-slate-600 border-slate-200';
  }
  return 'bg-emerald-50 text-emerald-700 border-emerald-100';
};

export default function Analysis() {
  const navigate = useNavigate();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

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
        if (!cancelled) {
          setReport(data);
        }
      } catch (err) {
        console.error('Failed to load stream analysis:', err);
        if (!cancelled) {
          setError(
            err?.response?.data?.detail ||
              'The analysis report could not be loaded.'
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
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

  const session = report?.session || {};
  const protocolSummary = report?.protocol_summary || {};

  const protocol = normalizeProtocol(protocolSummary.detected_protocol);
  const isEmailProtocol = ['SMTP', 'IMAP', 'POP3'].includes(protocol);
  const hasTls = protocolSummary.has_tls === true;

  const starttlsState = valueOrUnavailable(protocolSummary.starttls_status);


  const streamState = useMemo(() => {
    if (isEmailProtocol && hasTls) {
      return {
        label: 'TLS observed',
        detail: `${protocol} traffic with TLS evidence in the capture.`,
        icon: ShieldCheck,
        tone: 'emerald',
      };
    }

    if (isEmailProtocol && !hasTls) {
      return {
        label: 'No TLS observed',
        detail: `${protocol} traffic was detected, but no TLS handshake was reported for this capture.`,
        icon: ShieldAlert,
        tone: 'amber',
      };
    }

    if (hasTls) {
      return {
        label: 'TLS observed',
        detail: 'TLS traffic was detected, but an email protocol was not identified.',
        icon: LockKeyhole,
        tone: 'emerald',
      };
    }

    return {
      label: 'No email/TLS stream',
      detail: 'The backend did not report an email protocol or TLS evidence for this capture.',
      icon: Activity,
      tone: 'slate',
    };
  }, [hasTls, isEmailProtocol, protocol]);

  if (loading) {
    return (
      <div className="min-h-screen bg-white px-6 py-10">
        <div className="mx-auto flex min-h-[70vh] max-w-6xl items-center justify-center">
          <div className="flex flex-col items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-violet-50 text-violet-600">
              <RefreshCw className="h-5 w-5 animate-spin" />
            </div>
            <p className="text-sm font-semibold text-slate-600">
              Loading stream evidence...
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="min-h-screen bg-white px-6 py-10">
        <div className="mx-auto flex min-h-[70vh] max-w-2xl items-center justify-center">
          <Card className="w-full p-10 text-center">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-violet-50 text-violet-600">
              <TerminalSquare className="h-7 w-7" />
            </div>
            <h1 className="mt-5 text-2xl font-black tracking-tight text-slate-900">
              No active analysis
            </h1>
            <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">
              Upload a PCAP capture first. Stream Analysis will then show the
              protocol and security evidence reported by the backend.
            </p>
            <button
              type="button"
              onClick={() => navigate('/')}
              className="mt-6 inline-flex items-center gap-2 rounded-xl bg-violet-600 px-5 py-3 text-sm font-bold text-white shadow-lg shadow-violet-200 transition hover:bg-violet-700"
            >
              <Upload className="h-4 w-4" />
              Upload PCAP
            </button>
          </Card>
        </div>
      </div>
    );
  }

  const StreamIcon = streamState.icon;
  const streamTone = {
    emerald: {
      icon: 'bg-emerald-50 text-emerald-600',
      badge: 'bg-emerald-50 text-emerald-700 border-emerald-100',
    },
    amber: {
      icon: 'bg-amber-50 text-amber-600',
      badge: 'bg-amber-50 text-amber-700 border-amber-100',
    },
    slate: {
      icon: 'bg-slate-100 text-slate-600',
      badge: 'bg-slate-100 text-slate-600 border-slate-200',
    },
  }[streamState.tone];

  return (
    <div className="min-h-screen bg-white">
      <div className="mx-auto max-w-[1400px] px-6 py-8 lg:px-10">
        <div className="mb-8 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <button
              type="button"
              onClick={() => navigate('/dashboard')}
              className="mb-5 inline-flex items-center gap-2 text-xs font-bold text-slate-500 transition hover:text-violet-600"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to dashboard
            </button>

            <SectionLabel>Forensic Stream Analysis</SectionLabel>

            <h1 className="mt-2 text-4xl font-black tracking-[-0.04em] text-slate-950">
              Stream evidence
            </h1>

            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
              Protocol, transport-security, and STARTTLS evidence reported by
              the analysis pipeline for this capture.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="rounded-2xl border border-slate-100 bg-slate-50 px-4 py-3">
              <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
                Capture
              </p>
              <p className="mt-1 max-w-[280px] truncate text-sm font-bold text-slate-800">
                {session.filename || 'capture.pcap'}
              </p>
            </div>

            <button
              type="button"
              onClick={() => navigate('/')}
              className="inline-flex items-center gap-2 rounded-2xl border border-violet-200 bg-white px-4 py-3 text-sm font-bold text-violet-700 transition hover:border-violet-300 hover:bg-violet-50"
            >
              <Upload className="h-4 w-4" />
              New capture
            </button>
          </div>
        </div>

        {error && (
          <Card className="mb-6 border-red-100">
            <div className="flex items-start gap-4 p-5">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-red-50 text-red-600">
                <CircleAlert className="h-5 w-5" />
              </div>
              <div>
                <p className="font-bold text-slate-900">
                  Could not load stream analysis
                </p>
                <p className="mt-1 text-sm text-slate-500">{error}</p>
              </div>
            </div>
          </Card>
        )}

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-[0_12px_35px_rgba(71,38,130,0.06)]">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-violet-50 text-violet-600">
              <Layers3 className="h-5 w-5" />
            </div>
            <p className="mt-4 text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
              Total streams
            </p>
            <p className="mt-1 text-3xl font-black text-slate-950">
              {valueOrUnavailable(session.total_streams)}
            </p>
            <p className="mt-1 text-xs text-slate-500">
              Reconstructed TCP conversations
            </p>
          </div>

          <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-[0_12px_35px_rgba(71,38,130,0.06)]">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-50 text-emerald-600">
              <Mail className="h-5 w-5" />
            </div>
            <p className="mt-4 text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
              Detected protocol
            </p>
            <p className="mt-1 text-2xl font-black text-slate-950">
              {valueOrUnavailable(protocolSummary.detected_protocol)}
            </p>
            <p className="mt-1 text-xs text-slate-500">
              Reported by protocol classification
            </p>
          </div>

          <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-[0_12px_35px_rgba(71,38,130,0.06)]">
            <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${streamTone.icon}`}>
              <StreamIcon className="h-5 w-5" />
            </div>
            <p className="mt-4 text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
              Transport security
            </p>
            <p className="mt-1 text-xl font-black text-slate-950">
              {streamState.label}
            </p>
            <p className="mt-1 text-xs text-slate-500">
              {hasTls ? 'TLS evidence reported' : 'No TLS evidence reported'}
            </p>
          </div>

        </div>

        <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-[1.35fr_0.65fr]">
          <Card className="overflow-hidden">
            <div className="border-b border-slate-100 px-6 py-5 sm:px-7">
              <SectionLabel>Observed stream state</SectionLabel>
              <div className="mt-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="text-2xl font-black tracking-tight text-slate-950">
                    {protocol || 'Protocol not identified'}
                  </h2>
                  <p className="mt-1 text-sm text-slate-500">
                    {streamState.detail}
                  </p>
                </div>
                <span
                  className={`inline-flex w-fit items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-bold ${streamTone.badge}`}
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-current" />
                  {streamState.label}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-px bg-slate-100 sm:grid-cols-2">
              <div className="bg-white p-6">
                <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
                  STARTTLS state
                </p>
                <p className="mt-2 text-lg font-black text-slate-900">
                  {starttlsState}
                </p>
                <p className="mt-1 text-xs leading-5 text-slate-500">
                  State reported by the STARTTLS analysis stage.
                </p>
              </div>

              <div className="bg-white p-6">
                <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
                  TLS version
                </p>
                <p className="mt-2 text-lg font-black text-slate-900">
                  {valueOrUnavailable(protocolSummary.tls_version)}
                </p>
                <p className="mt-1 text-xs leading-5 text-slate-500">
                  Only shown when TLS version evidence was extracted.
                </p>
              </div>

              <div className="bg-white p-6">
                <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
                  Cipher suite
                </p>
                <p className="mt-2 break-words text-sm font-black text-slate-900">
                  {valueOrUnavailable(protocolSummary.cipher_suite)}
                </p>
                <p className="mt-1 text-xs leading-5 text-slate-500">
                  Reported from captured TLS negotiation evidence.
                </p>
              </div>

              <div className="bg-white p-6">
                <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-400">
                  Key exchange
                </p>
                <p className="mt-2 text-lg font-black text-slate-900">
                  {valueOrUnavailable(protocolSummary.key_exchange)}
                </p>
                <p className="mt-1 text-xs leading-5 text-slate-500">
                  Reported cryptographic parameter, when available.
                </p>
              </div>
            </div>
          </Card>

          <Card className="p-6 sm:p-7">
            <SectionLabel>Capture context</SectionLabel>

            <div className="mt-5 space-y-3">
              <div className="flex items-center justify-between gap-4 rounded-2xl bg-slate-50 px-4 py-3.5">
                <div className="flex items-center gap-3">
                  <Network className="h-4 w-4 text-violet-600" />
                  <span className="text-sm font-semibold text-slate-600">Protocol</span>
                </div>
                <span className="font-mono text-xs font-bold text-slate-900">
                  {valueOrUnavailable(protocolSummary.detected_protocol)}
                </span>
              </div>

              <div className="flex items-center justify-between gap-4 rounded-2xl bg-slate-50 px-4 py-3.5">
                <div className="flex items-center gap-3">
                  <LockKeyhole className="h-4 w-4 text-violet-600" />
                  <span className="text-sm font-semibold text-slate-600">TLS</span>
                </div>
                <span className={`rounded-full border px-2.5 py-1 text-xs font-bold ${hasTls ? 'border-emerald-100 bg-emerald-50 text-emerald-700' : 'border-amber-100 bg-amber-50 text-amber-700'}`}>
                  {hasTls ? 'Observed' : 'Not observed'}
                </span>
              </div>

              <div className="flex items-center justify-between gap-4 rounded-2xl bg-slate-50 px-4 py-3.5">
                <div className="flex items-center gap-3">
                  <Layers3 className="h-4 w-4 text-violet-600" />
                  <span className="text-sm font-semibold text-slate-600">Streams</span>
                </div>
                <span className="text-sm font-black text-slate-900">
                  {valueOrUnavailable(session.total_streams)}
                </span>
              </div>

              <div className="flex items-center justify-between gap-4 rounded-2xl bg-slate-50 px-4 py-3.5">
                <div className="flex items-center gap-3">
                  <TerminalSquare className="h-4 w-4 text-violet-600" />
                  <span className="text-sm font-semibold text-slate-600">Status</span>
                </div>
                <span className="rounded-full border border-emerald-100 bg-emerald-50 px-2.5 py-1 text-xs font-bold text-emerald-700">
                  {valueOrUnavailable(session.status)}
                </span>
              </div>
            </div>

            <div className="mt-6 rounded-2xl border border-violet-100 bg-violet-50/60 p-4">
              <p className="text-xs font-bold text-violet-900">
                Why this stream is shown
              </p>
              <p className="mt-1 text-xs leading-5 text-violet-800/70">
                This view uses the backend report directly. It does not infer an
                encrypted stream merely because a TCP stream exists.
              </p>
            </div>
          </Card>
        </div>

        <div className="mt-6 flex justify-center">
          <button
            type="button"
            onClick={() => navigate('/findings')}
            className="inline-flex items-center gap-2 rounded-xl bg-violet-600 px-6 py-3 text-sm font-bold text-white shadow-lg shadow-violet-200 transition hover:bg-violet-700 active:scale-[0.98]"
          >
            See all findings
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
