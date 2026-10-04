import React, { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  LockKeyhole,
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  FileCheck2,
  Cpu,
  RefreshCw,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  Layers,
} from 'lucide-react';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { LoadingState } from '../components/LoadingScreen';
import { valueOrUnavailable } from '../utils/formatters';
import { severityBadgeClasses, statusBadgeClasses } from '../utils/severity';

export default function TLSAnalysis() {
  const navigate = useNavigate();
  const { report, loading } = useAnalysis();

  const session = report?.session;
  const protocolSummary = report?.protocol_summary;
  const featureVector = report?.feature_vector;

  const tlsFindings = useMemo(() => {
    const list = Array.isArray(report?.compliance_findings) ? report.compliance_findings : [];
    return list.filter((f) => {
      const cat = String(f.category || '').toUpperCase();
      return (
        cat.includes('TLS') ||
        cat.includes('CIPHER') ||
        cat.includes('KEY_EXCHANGE') ||
        cat.includes('CERTIFICATE') ||
        cat.includes('STARTTLS') ||
        cat.includes('IDENTITY')
      );
    });
  }, [report]);

  if (loading) {
    return (
      <LoadingState
        title="TLS & PKI Inspection"
        message="Auditing handshake ciphers, key exchanges, certificate validity, and trust chains..."
      />
    );
  }

  if (!report || !session) {
    return (
      <EmptyAnalysisState
        title="START ANALYSIS"
        description="Upload a PCAP to inspect TLS and PKI security."
        buttonText="Start Analysis"
        featureBadge="TLS & PKI Audit"
      />
    );
  }

  const hasTls = Boolean(protocolSummary?.has_tls);

  return (
    <div className="relative min-h-screen bg-[#F7F7F5] px-6 py-8 lg:px-10">
      <div className="relative z-10 mx-auto max-w-[1400px]">
        <PageHeader
          category="Cryptographic Audit"
          title="TLS & PKI Analysis"
          description="Deterministic inspection of TLS record negotiation, cipher suite strength, forward secrecy, and X.509 certificate trust."
          session={session}
          actions={
            <button
              type="button"
              onClick={() => navigate('/evidence')}
              className="inline-flex items-center gap-2 rounded-xl bg-[#111111] px-4 py-2.5 text-xs font-bold text-white shadow-sm transition hover:bg-[#222222]"
            >
              Explore Evidence Records
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          }
        />

        {/* TLS Overview Banner */}
        <div className={`mb-8 rounded-3xl border p-6 shadow-sm ${hasTls ? 'border-emerald-200 bg-emerald-50/50' : 'border-amber-200 bg-amber-50/50'}`}>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className={`flex h-12 w-12 items-center justify-center rounded-2xl ${hasTls ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                <LockKeyhole className="h-6 w-6" />
              </div>
              <div>
                <h2 className="text-xl font-black text-slate-900">
                  {hasTls ? 'TLS Encryption Observed' : 'Plaintext / Unencrypted Session'}
                </h2>
                <p className="text-xs text-slate-600">
                  {hasTls
                    ? `Handshake negotiation confirmed (${protocolSummary?.tls_version || 'TLS'})`
                    : 'No cryptographic handshake detected. Cleartext communication or downgrade suspected.'}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 font-mono text-xs font-bold text-slate-800">
                STARTTLS: {valueOrUnavailable(protocolSummary?.starttls_status, 'None')}
              </span>
            </div>
          </div>
        </div>

        {/* Cryptographic Parameters Grid */}
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
          {/* Protocol & Handshake */}
          <div className="rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm">
            <div className="flex items-center gap-3 border-b border-[#E5E5E0] pb-3">
              <div className="rounded-xl bg-[#111111] p-2 text-white">
                <Cpu className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-[#111111]">Handshake & Protocol</h3>
                <p className="text-[11px] text-[#888888]">Negotiation versions</p>
              </div>
            </div>

            <div className="mt-4 space-y-3">
              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">Application Protocol</p>
                <p className="mt-0.5 font-mono text-xs font-bold text-[#111111]">
                  {valueOrUnavailable(protocolSummary?.detected_protocol)}
                </p>
              </div>

              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">Negotiated TLS Version</p>
                <p className="mt-0.5 font-mono text-xs font-bold text-[#111111]">
                  {valueOrUnavailable(protocolSummary?.tls_version)}
                </p>
              </div>

              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">STARTTLS Transition</p>
                <p className="mt-0.5 font-mono text-xs font-bold text-[#111111]">
                  {valueOrUnavailable(protocolSummary?.starttls_status)}
                </p>
              </div>

              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">JA4 Client Fingerprint</p>
                <p className="mt-0.5 font-mono text-xs text-[#555555]">
                  {featureVector?.ja4_available === 1.0 ? 'Observed in Client Hello' : 'Unavailable from captured evidence'}
                </p>
              </div>
            </div>
          </div>

          {/* Cipher & Key Exchange */}
          <div className="rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm">
            <div className="flex items-center gap-3 border-b border-[#E5E5E0] pb-3">
              <div className="rounded-xl bg-[#111111] p-2 text-white">
                <KeyRound className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-[#111111]">Cipher & Key Exchange</h3>
                <p className="text-[11px] text-[#888888]">Cryptographic primitives</p>
              </div>
            </div>

            <div className="mt-4 space-y-3">
              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">Cipher Suite</p>
                <p className="mt-0.5 break-words font-mono text-xs font-bold text-[#111111]">
                  {valueOrUnavailable(protocolSummary?.cipher_suite)}
                </p>
              </div>

              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">Key Exchange Algorithm</p>
                <p className="mt-0.5 font-mono text-xs font-bold text-[#111111]">
                  {valueOrUnavailable(protocolSummary?.key_exchange)}
                </p>
              </div>

              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">Perfect Forward Secrecy (PFS)</p>
                <div className="mt-1 flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${protocolSummary?.perfect_forward_secrecy ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                  <p className="font-mono text-xs font-bold text-[#111111]">
                    {protocolSummary?.perfect_forward_secrecy ? 'ENABLED (Ephemeral DH/ECDH)' : 'DISABLED / NOT OBSERVED'}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* X.509 & PKI Identity */}
          <div className="rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm">
            <div className="flex items-center gap-3 border-b border-[#E5E5E0] pb-3">
              <div className="rounded-xl bg-[#111111] p-2 text-white">
                <FileCheck2 className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-[#111111]">X.509 & Certificate Trust</h3>
                <p className="text-[11px] text-[#888888]">Identity validation</p>
              </div>
            </div>

            <div className="mt-4 space-y-3">
              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">Validity State</p>
                <p className="mt-0.5 font-mono text-xs font-bold text-[#111111]">
                  {valueOrUnavailable(protocolSummary?.certificate_validity)}
                </p>
              </div>

              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">Key Size / Signature Algorithm</p>
                <p className="mt-0.5 font-mono text-xs text-[#111111]">
                  {protocolSummary?.certificate_key_size ? `${protocolSummary.certificate_key_size} bits` : 'Key size unavailable'} · {valueOrUnavailable(protocolSummary?.signature_algorithm, 'Signature unavailable')}
                </p>
              </div>

              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">SAN / Hostname Alignment</p>
                <p className="mt-0.5 font-mono text-xs text-[#111111]">
                  {valueOrUnavailable(protocolSummary?.san_match_status)}
                </p>
              </div>

              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">Trust & Revocation</p>
                <p className="mt-0.5 font-mono text-xs text-[#111111]">
                  Trust: {valueOrUnavailable(protocolSummary?.trust_validation)} · Revocation: {valueOrUnavailable(protocolSummary?.revocation_status)}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Cryptographic Compliance Findings */}
        <div className="mt-8 rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm">
          <div className="flex items-center justify-between border-b border-[#E5E5E0] pb-4">
            <div>
              <h2 className="text-lg font-black text-[#111111]">Cryptographic Rules & Policy Evaluation</h2>
              <p className="text-xs text-[#666666]">Deterministic rule violations pertaining to TLS, ciphers, and certificates</p>
            </div>
            <span className="rounded-full border border-[#E5E5E0] bg-[#F7F7F5] px-3 py-1 font-mono text-xs font-bold text-[#111111]">
              {tlsFindings.length} Evaluated Finding{tlsFindings.length === 1 ? '' : 's'}
            </span>
          </div>

          <div className="mt-5 divide-y divide-[#E5E5E0]">
            {tlsFindings.length === 0 ? (
              <div className="py-12 text-center text-xs text-[#666666]">
                <ShieldCheck className="mx-auto h-8 w-8 text-emerald-500" />
                <p className="mt-2 font-bold text-[#111111]">
                  {!hasTls
                    ? 'No TLS encryption observed'
                    : 'No cryptographic violations recorded'}
                </p>
                <p className="mt-1">
                  {!hasTls
                    ? 'No TLS handshake was observed in captured traffic; PKI cryptographic rules were not applicable.'
                    : 'All observable TLS and certificate parameters met compliance policies.'}
                </p>
              </div>
            ) : (
              tlsFindings.map((f, i) => (
                <div key={f.finding_id || i} className="py-4 first:pt-0 last:pb-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-extrabold ${severityBadgeClasses(f.severity)}`}>
                      {f.severity}
                    </span>
                    <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-extrabold ${statusBadgeClasses(f.status)}`}>
                      {f.status}
                    </span>
                    <span className="font-mono text-[10px] font-bold text-[#888888]">{f.rule_id}</span>
                  </div>

                  <h3 className="mt-2 text-sm font-black text-[#111111]">{f.title}</h3>
                  <p className="mt-1 text-xs text-[#555555]">{f.description}</p>

                  {f.recommendation && (
                    <div className="mt-2.5 rounded-xl border border-[#E5E5E0] bg-[#F7F7F5] p-2.5 text-xs text-[#111111]">
                      <span className="font-bold">Remediation:</span> {f.recommendation}
                    </div>
                  )}

                  {f.evidence && (
                    <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-[#666666]">
                      <span>Observed: <strong className="text-[#111111]">{String(f.evidence.observed_value)}</strong></span>
                      {f.evidence.reference_value && <span>Expected: <strong className="text-[#111111]">{String(f.evidence.reference_value)}</strong></span>}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
