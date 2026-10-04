import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  ChevronDown,
  FileWarning,
  Filter,
  ShieldCheck,
  RefreshCw,
  Search,
  ExternalLink,
  BookOpen,
  ArrowRight,
} from 'lucide-react';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { valueOrUnavailable, formatTimestamp } from '../utils/formatters';
import { severityBadgeClasses, statusBadgeClasses, severityDotClasses } from '../utils/severity';
import { isReportApplicable, getApplicabilityReason } from '../utils/reportModel';

export default function Findings() {
  const navigate = useNavigate();
  const { report, loading } = useAnalysis();

  const isApplicable = isReportApplicable(report);
  const applicabilityReason =
    getApplicabilityReason(report) ||
    'No supported email protocol/security assessment was observed in this capture.';

  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [expanded, setExpanded] = useState(null);

  const session = report?.session;
  const findings = useMemo(
    () => (Array.isArray(report?.compliance_findings) ? report.compliance_findings : []),
    [report]
  );
  const vulnerabilityMappings = useMemo(
    () => (Array.isArray(report?.vulnerability_mappings) ? report.vulnerability_mappings : []),
    [report]
  );

  // Map vulnerability mappings by source_finding_id
  const mappingsByFindingId = useMemo(() => {
    const map = new Map();
    vulnerabilityMappings.forEach((vm) => {
      if (vm.source_finding_id) {
        if (!map.has(vm.source_finding_id)) map.set(vm.source_finding_id, []);
        map.get(vm.source_finding_id).push(vm);
      }
    });
    return map;
  }, [vulnerabilityMappings]);

  // Aggregate stats
  const counts = useMemo(() => {
    return {
      total: findings.length,
      critical: findings.filter((f) => String(f.severity).toUpperCase() === 'CRITICAL').length,
      high: findings.filter((f) => String(f.severity).toUpperCase() === 'HIGH').length,
      medium: findings.filter((f) => String(f.severity).toUpperCase() === 'MEDIUM').length,
      low: findings.filter((f) => String(f.severity).toUpperCase() === 'LOW').length,
      cweMapped: vulnerabilityMappings.length,
    };
  }, [findings, vulnerabilityMappings]);

  // Extract unique categories
  const categories = useMemo(() => {
    const set = new Set();
    findings.forEach((f) => {
      if (f.category) set.add(String(f.category));
    });
    return Array.from(set);
  }, [findings]);

  // Filtered list
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const sev = String(f.severity || '').toUpperCase();
      const st = String(f.status || '').toUpperCase();
      const cat = String(f.category || '');

      const matchesSev = severityFilter === 'ALL' || sev === severityFilter;
      const matchesSt = statusFilter === 'ALL' || st === statusFilter;
      const matchesCat = categoryFilter === 'ALL' || cat === categoryFilter;

      const term = searchTerm.toLowerCase().trim();
      const matchesSearch =
        !term ||
        f.title?.toLowerCase().includes(term) ||
        f.description?.toLowerCase().includes(term) ||
        f.rule_id?.toLowerCase().includes(term) ||
        f.finding_id?.toLowerCase().includes(term);

      return matchesSev && matchesSt && matchesCat && matchesSearch;
    });
  }, [findings, severityFilter, statusFilter, categoryFilter, searchTerm]);

  if (loading) {
    return (
      <div className="flex min-h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <RefreshCw className="h-6 w-6 animate-spin text-[#0B5ED7]" />
          <p className="text-sm font-semibold text-slate-600">Loading finding catalog...</p>
        </div>
      </div>
    );
  }

  if (!report || !session) {
    return (
      <EmptyAnalysisState
        title="No active findings"
        description="Upload a PCAP capture to evaluate deterministic compliance rules and CVE correlations."
      />
    );
  }

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#f8fbff] px-6 py-8 lg:px-10">
      <div className="relative z-10 mx-auto max-w-[1400px]">
        <PageHeader
          category="Deterministic Security Review"
          title="Findings & CVEs"
          description="Authoritative security rule violations and linked Common Weakness Enumerations (CWE/CVE) evaluated against passive capture evidence."
          session={session}
          actions={
            <button
              type="button"
              onClick={() => navigate('/posture')}
              className="inline-flex items-center gap-2 rounded-xl bg-white border border-blue-200 px-4 py-2.5 text-xs font-bold text-[#0B5ED7] shadow-sm transition hover:bg-blue-50"
            >
              <BookOpen className="h-3.5 w-3.5" />
              View Security Posture & Rules
            </button>
          }
        />

        {!isApplicable && (
          <div className="mb-6 rounded-2xl border border-amber-200 bg-amber-50/90 p-4 shadow-sm flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-bold text-amber-900">
                Assessment Not Applicable
              </h3>
              <p className="mt-0.5 text-xs text-amber-800 leading-relaxed">
                {applicabilityReason} No deterministic compliance findings were evaluated.
              </p>
            </div>
          </div>
        )}

        {/* Severity Metrics */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
          <div className="rounded-2xl border border-slate-100 bg-white p-4 shadow-sm">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">Total Findings</span>
            <p className="mt-1 text-2xl font-black text-slate-900">{counts.total}</p>
          </div>
          <div className="rounded-2xl border border-red-100 bg-red-50/40 p-4 shadow-sm">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-red-600">Critical</span>
            <p className="mt-1 text-2xl font-black text-red-700">{counts.critical}</p>
          </div>
          <div className="rounded-2xl border border-orange-100 bg-orange-50/40 p-4 shadow-sm">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-orange-600">High</span>
            <p className="mt-1 text-2xl font-black text-orange-700">{counts.high}</p>
          </div>
          <div className="rounded-2xl border border-amber-100 bg-amber-50/40 p-4 shadow-sm">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-amber-600">Medium</span>
            <p className="mt-1 text-2xl font-black text-amber-700">{counts.medium}</p>
          </div>
          <div className="rounded-2xl border border-slate-200 bg-slate-100/60 p-4 shadow-sm">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-500">Low / Info</span>
            <p className="mt-1 text-2xl font-black text-slate-700">{counts.low}</p>
          </div>
          <div className="rounded-2xl border border-blue-100 bg-blue-50/50 p-4 shadow-sm">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#0B5ED7]">CWE / CVE Mappings</span>
            <p className="mt-1 text-2xl font-black text-[#0B5ED7]">{counts.cweMapped}</p>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="mt-6 rounded-3xl border border-blue-100 bg-white p-5 shadow-sm">
          <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search findings by rule, title, or keyword..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full rounded-2xl border border-slate-200 bg-slate-50/60 py-2 pl-10 pr-4 text-xs font-medium text-slate-900 outline-none transition focus:border-[#0B5ED7] focus:bg-white"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-400">
                <Filter className="h-3.5 w-3.5" />
                Severity:
              </div>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setSeverityFilter(s)}
                  className={`rounded-xl border px-2.5 py-1.5 text-xs font-bold transition ${
                    severityFilter === s
                      ? 'border-[#0B5ED7] bg-[#0B5ED7] text-white'
                      : 'border-slate-200 bg-white text-slate-600 hover:border-blue-200'
                  }`}
                >
                  {s === 'ALL' ? 'All' : s}
                </button>
              ))}

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-bold text-slate-600 outline-none focus:border-[#0B5ED7]"
              >
                <option value="ALL">All Statuses</option>
                <option value="NON_COMPLIANT">Non-Compliant</option>
                <option value="COMPLIANT">Compliant</option>
                <option value="UNKNOWN">Unknown</option>
                <option value="NOT_APPLICABLE">Not Applicable</option>
              </select>

              {categories.length > 0 && (
                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-bold text-slate-600 outline-none focus:border-[#0B5ED7]"
                >
                  <option value="ALL">All Categories</option>
                  {categories.map((c) => (
                    <option key={c} value={c}>{c}</option>
                  ))}
                </select>
              )}
            </div>
          </div>
        </div>

        {/* Findings Accordion List */}
        <div className="mt-6 space-y-4">
          {filteredFindings.length === 0 ? (
            <div className="rounded-3xl border border-blue-100 bg-white p-12 text-center shadow-sm">
              <ShieldCheck className="mx-auto h-10 w-10 text-emerald-500" />
              <h3 className="mt-3 text-base font-black text-slate-900">No findings match the current filters</h3>
              <p className="mt-1 text-xs text-slate-500">Try broadening your search term or filter criteria.</p>
            </div>
          ) : (
            filteredFindings.map((finding) => {
              const key = finding.finding_id || finding.rule_id;
              const isOpen = expanded === key;
              const linkedWeaknesses = mappingsByFindingId.get(finding.finding_id) || [];

              return (
                <div
                  key={key}
                  className="rounded-3xl border border-blue-100/90 bg-white p-6 shadow-sm transition hover:border-blue-200"
                >
                  <button
                    type="button"
                    onClick={() => setExpanded(isOpen ? null : key)}
                    className="w-full text-left"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-extrabold ${severityBadgeClasses(finding.severity)}`}>
                          <span className={`inline-block h-1.5 w-1.5 rounded-full mr-1.5 ${severityDotClasses(finding.severity)}`} />
                          {finding.severity}
                        </span>

                        <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-extrabold ${statusBadgeClasses(finding.status)}`}>
                          {finding.status}
                        </span>

                        <span className="font-mono text-[10px] font-bold text-slate-400">
                          {finding.rule_id}
                        </span>

                        {finding.category && (
                          <span className="rounded-lg border border-slate-100 bg-slate-50 px-2 py-0.5 text-[10px] font-bold text-slate-500">
                            {finding.category}
                          </span>
                        )}
                      </div>

                      <ChevronDown
                        className={`h-5 w-5 shrink-0 text-slate-400 transition-transform ${isOpen ? 'rotate-180 text-[#0B5ED7]' : ''}`}
                      />
                    </div>

                    <h3 className="mt-3 text-base font-black text-slate-950">{finding.title}</h3>
                    <p className="mt-1 text-xs leading-5 text-slate-600">{finding.description}</p>
                  </button>

                  {/* Expanded Detail Panel */}
                  {isOpen && (
                    <div className="mt-5 border-t border-slate-100 pt-5 space-y-4">
                      {/* Remediation Guidance */}
                      {finding.recommendation && (
                        <div className="rounded-2xl border border-blue-100 bg-blue-50/50 p-4">
                          <p className="text-[10px] font-bold uppercase tracking-wider text-[#084FB8]">Actionable Remediation Guidance</p>
                          <p className="mt-1 text-xs leading-5 font-semibold text-slate-800">{finding.recommendation}</p>
                        </div>
                      )}

                      {/* Traceable Evidence Grid (Bug 4 Fix) */}
                      <div className="rounded-2xl border border-slate-100 bg-slate-50/70 p-4">
                        <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Traceable Forensic Evidence</p>
                        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4 text-xs font-mono">
                          <div>
                            <span className="text-[10px] uppercase text-slate-400">Observed Property</span>
                            <p className="mt-0.5 font-bold text-slate-800 break-words">{valueOrUnavailable(finding.evidence?.observed_property)}</p>
                          </div>

                          <div>
                            <span className="text-[10px] uppercase text-slate-400">Observed Value</span>
                            <p className="mt-0.5 font-bold text-slate-900 break-words">{valueOrUnavailable(finding.evidence?.observed_value)}</p>
                          </div>

                          <div>
                            <span className="text-[10px] uppercase text-slate-400">Expected Reference</span>
                            <p className="mt-0.5 font-bold text-slate-700 break-words">{valueOrUnavailable(finding.evidence?.reference_value, 'Standard baseline')}</p>
                          </div>

                          <div>
                            <span className="text-[10px] uppercase text-slate-400">Stream / Frame Anchor</span>
                            <p className="mt-0.5 font-bold text-slate-800">
                              {finding.evidence?.stream_id ? String(finding.evidence.stream_id).slice(0, 18) : 'Session'}
                              {finding.evidence?.packet_number && ` · Frame #${finding.evidence.packet_number}`}
                            </p>
                          </div>
                        </div>
                      </div>

                      {/* Correlated CWE / CVE Mappings */}
                      {linkedWeaknesses.length > 0 && (
                        <div className="rounded-2xl border border-purple-100 bg-purple-50/30 p-4">
                          <div className="flex items-center gap-2">
                            <span className="rounded bg-purple-100 px-2 py-0.5 text-[10px] font-extrabold text-purple-700">
                              CORRELATED WEAKNESS
                            </span>
                            <span className="text-xs font-bold text-purple-900">Mapped Industry Standards</span>
                          </div>

                          <div className="mt-3 space-y-3">
                            {linkedWeaknesses.map((w) => (
                              <div key={w.mapping_id} className="rounded-xl border border-purple-100 bg-white p-3 text-xs">
                                <div className="flex items-center justify-between">
                                  <span className="font-mono font-black text-purple-800">{w.identifier}</span>
                                  {w.vulnerability_id && (
                                    <span className="rounded bg-red-100 px-2 py-0.5 font-mono text-[10px] font-bold text-red-700">
                                      {w.vulnerability_id}
                                    </span>
                                  )}
                                  <span className="text-[10px] text-slate-400">Confidence: {w.confidence}</span>
                                </div>
                                <p className="mt-1 font-bold text-slate-800">{w.title}</p>
                                <p className="mt-1 text-slate-600 text-[11px] leading-relaxed">{w.rationale}</p>
                                {w.references && w.references.length > 0 && (
                                  <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-slate-500">
                                    <span>References:</span>
                                    {w.references.map((ref, idx) => (
                                      <span key={idx} className="font-mono underline">{ref}</span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Engine Metadata */}
                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span>Engine Version: {finding.engine_version || '21.0.0'} · Deterministic: {String(finding.deterministic)}</span>
                        <span className="font-mono">{finding.finding_id}</span>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
