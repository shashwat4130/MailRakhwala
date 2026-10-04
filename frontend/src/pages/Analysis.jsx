import React, { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  FileText,
  Layers3,
  LockKeyhole,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  Upload,
  ChevronRight,
} from 'lucide-react';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { valueOrUnavailable, formatBytes, formatTimestamp } from '../utils/formatters';
import { severityBadgeClasses, statusBadgeClasses } from '../utils/severity';

export default function Analysis() {
  const navigate = useNavigate();
  const { report, loading, error } = useAnalysis();

  const session = report?.session;
  const protocolSummary = report?.protocol_summary;
  const findings = useMemo(
    () => (Array.isArray(report?.compliance_findings) ? report.compliance_findings : []),
    [report]
  );

  // Extract unique stream identifiers from forensic evidence
  const observedStreamIds = useMemo(() => {
    const ids = new Set();
    if (report?.posture_report?.stream_id) ids.add(report.posture_report.stream_id);
    if (report?.feature_vector?.stream_id) ids.add(report.feature_vector.stream_id);
    findings.forEach((f) => {
      if (f.evidence?.stream_id) ids.add(f.evidence.stream_id);
    });
    return Array.from(ids);
  }, [report, findings]);

  if (loading) {
    return (
      <div className="flex min-h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <RefreshCw className="h-6 w-6 animate-spin text-[#0B5ED7]" />
          <p className="text-sm font-semibold text-slate-600">Loading stream forensics...</p>
        </div>
      </div>
    );
  }

  if (!report || !session) {
    return (
      <EmptyAnalysisState
        title="No active stream analysis"
        description="Upload a PCAP capture to reconstruct email sessions and inspect stream evidence."
      />
    );
  }

  const detectedProtocol = protocolSummary?.detected_protocol || 'Non-Email';
  const hasTls = Boolean(protocolSummary?.has_tls);
  const totalStreams = session.total_streams ?? observedStreamIds.length;

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#f8fbff] px-6 py-8 lg:px-10">
      <div className="relative z-10 mx-auto max-w-[1400px]">
        <PageHeader
          category="Forensic Stream Investigation"
          title="Stream Analysis"
          description="Protocol identification, transport security boundaries, and session indicators evaluated from passive capture."
          session={session}
          actions={
            <button
              type="button"
              onClick={() => navigate('/tls-analysis')}
              className="inline-flex items-center gap-2 rounded-xl bg-[#0B5ED7] px-4 py-2.5 text-xs font-bold text-white shadow-sm transition hover:bg-[#084FB8]"
            >
              <LockKeyhole className="h-3.5 w-3.5" />
              Inspect TLS Parameters
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          }
        />

        {error && (
          <div className="mb-6 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
            {error}
          </div>
        )}

        {/* Stream Metrics Grid */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-2xl border border-blue-100 bg-white p-5 shadow-sm">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">Total Streams</span>
              <Layers3 className="h-4 w-4 text-[#0B5ED7]" />
            </div>
            <p className="mt-2 text-2xl font-black text-slate-900">{totalStreams}</p>
            <p className="mt-1 text-xs text-slate-500">Evaluated TCP streams</p>
          </div>

          <div className="rounded-2xl border border-blue-100 bg-white p-5 shadow-sm">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">Detected Protocol</span>
              <Network className="h-4 w-4 text-[#0B5ED7]" />
            </div>
            <p className="mt-2 text-2xl font-black text-slate-900">{detectedProtocol}</p>
            <p className="mt-1 text-xs text-slate-500">Application classification</p>
          </div>

          <div className="rounded-2xl border border-blue-100 bg-white p-5 shadow-sm">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">Transport Security</span>
              <LockKeyhole className="h-4 w-4 text-[#0B5ED7]" />
            </div>
            <div className="mt-2 flex items-center gap-2">
              <span className={`h-2.5 w-2.5 rounded-full ${hasTls ? 'bg-emerald-500' : 'bg-amber-500'}`} />
              <p className="text-xl font-black text-slate-900">{hasTls ? 'Encrypted (TLS)' : 'Plaintext'}</p>
            </div>
            <p className="mt-1 text-xs text-slate-500">{hasTls ? 'Cryptographic handshake observed' : 'Cleartext payload'}</p>
          </div>

          <div className="rounded-2xl border border-blue-100 bg-white p-5 shadow-sm">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">Pipeline Status</span>
              <CheckCircle2 className="h-4 w-4 text-emerald-600" />
            </div>
            <p className="mt-2 text-2xl font-black text-emerald-700">{session.status}</p>
            <p className="mt-1 text-xs text-slate-500">{formatBytes(session.filesize_bytes)}</p>
          </div>
        </div>

        {/* Stream Session Investigation Panel */}
        <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-[1.2fr_0.8fr]">
          <div className="rounded-3xl border border-blue-100 bg-white p-6 shadow-sm">
            <div className="flex items-center justify-between border-b border-slate-100 pb-4">
              <div>
                <h2 className="text-lg font-black text-slate-900">Observed Stream Context</h2>
                <p className="text-xs text-slate-500">Identifiers and parameters reconstructed from the PCAP</p>
              </div>
              <span className="rounded-full border border-blue-100 bg-blue-50 px-3 py-1 font-mono text-xs font-bold text-[#0B5ED7]">
                Session ID: {String(session.session_id).slice(0, 12)}…
              </span>
            </div>

            <div className="mt-5 space-y-4">
              <div className="rounded-2xl border border-slate-100 bg-slate-50/70 p-4">
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">Reconstructed Stream Endpoints</p>
                {observedStreamIds.length > 0 ? (
                  <div className="mt-2 space-y-2">
                    {observedStreamIds.map((sid, idx) => (
                      <div key={idx} className="flex items-center gap-2 font-mono text-xs font-bold text-slate-800">
                        <span className="h-1.5 w-1.5 rounded-full bg-[#0B5ED7]" />
                        {sid}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mt-2 font-mono text-xs text-slate-500">No explicit stream identifier recorded.</p>
                )}
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="rounded-2xl border border-slate-100 bg-slate-50/70 p-4">
                  <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">STARTTLS State</p>
                  <p className="mt-1 font-mono text-xs font-bold text-slate-900">
                    {valueOrUnavailable(protocolSummary?.starttls_status)}
                  </p>
                </div>

                <div className="rounded-2xl border border-slate-100 bg-slate-50/70 p-4">
                  <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">TLS Negotiation</p>
                  <p className="mt-1 font-mono text-xs font-bold text-slate-900">
                    {valueOrUnavailable(protocolSummary?.tls_version)}
                  </p>
                </div>
              </div>

              <div className="rounded-2xl border border-blue-50 bg-blue-50/40 p-4 text-xs text-slate-600">
                <span className="font-bold text-[#0B5ED7]">Forensic Principle:</span> Email protocol classification requires observable RFC command sequences (e.g. EHLO/HELO, CAPA, USER) or dedicated TLS port bindings. A TCP connection alone does not constitute an email assessment.
              </div>
            </div>
          </div>

          {/* Associated Findings Summary */}
          <div className="rounded-3xl border border-blue-100 bg-white p-6 shadow-sm">
            <div className="flex items-center justify-between border-b border-slate-100 pb-4">
              <div>
                <h2 className="text-lg font-black text-slate-900">Stream Findings</h2>
                <p className="text-xs text-slate-500">Compliance violations identified in this stream</p>
              </div>
              <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-bold text-slate-700">
                {findings.length} findings
              </span>
            </div>

            <div className="mt-4 max-h-[380px] overflow-y-auto space-y-3 pr-1 scrollbar-thin">
              {findings.length === 0 ? (
                <div className="py-10 text-center text-xs text-slate-500">
                  <ShieldCheck className="mx-auto h-8 w-8 text-emerald-500" />
                  <p className="mt-2 font-bold text-slate-700">
                    {detectedProtocol === 'Non-Email' ? 'No email compliance findings evaluated' : 'No violations observed'}
                  </p>
                  <p className="mt-1">
                    {detectedProtocol === 'Non-Email'
                      ? 'The capture was classified as Non-Email traffic; RFC email rules were not evaluated.'
                      : 'All observable stream parameters met compliance baseline rules.'}
                  </p>
                </div>
              ) : (
                findings.map((f, i) => (
                  <div
                    key={f.finding_id || i}
                    onClick={() => navigate('/findings')}
                    className="group cursor-pointer rounded-2xl border border-slate-100 bg-slate-50/60 p-3.5 transition hover:border-blue-200 hover:bg-white hover:shadow-sm"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className={`rounded-full border px-2 py-0.5 text-[10px] font-extrabold ${severityBadgeClasses(f.severity)}`}>
                        {f.severity}
                      </span>
                      <span className="font-mono text-[10px] text-slate-400">{f.rule_id}</span>
                    </div>
                    <p className="mt-2 text-xs font-bold text-slate-900 group-hover:text-[#0B5ED7]">{f.title}</p>
                    <p className="mt-1 line-clamp-2 text-[11px] text-slate-500">{f.description}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
