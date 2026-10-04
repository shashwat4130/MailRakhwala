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
import { LoadingState } from '../components/LoadingScreen';
import { valueOrUnavailable, formatTimestamp } from '../utils/formatters';
import { severityBadgeClasses, statusBadgeClasses, severityDotClasses } from '../utils/severity';
import {
  isReportApplicable,
  getApplicabilityReason,
  getReportAnalytics,
  CANONICAL_RULES_COUNT,
} from '../utils/reportModel';

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
  const analytics = useMemo(() => getReportAnalytics(report), [report]);

  const vulnerabilityMappings = useMemo(
    () => (Array.isArray(report?.vulnerability_mappings) ? report.vulnerability_mappings : []),
    [report]
  );

  // Map vulnerability mappings by rule ID or finding ID
  const mappingsByRuleId = useMemo(() => {
    const map = new Map();
    vulnerabilityMappings.forEach((vm) => {
      const keys = [vm.source_rule_id, vm.rule_id, vm.source_finding_id].filter(Boolean);
      keys.forEach((key) => {
        if (!map.has(key)) map.set(key, []);
        map.get(key).push(vm);
      });
    });
    return map;
  }, [vulnerabilityMappings]);

  // Extract unique categories from grouped rules
  const categories = useMemo(() => {
    const set = new Set();
    analytics.allGroupedRules.forEach((r) => {
      if (r.category) set.add(String(r.category));
    });
    return Array.from(set);
  }, [analytics.allGroupedRules]);

  // Filtered grouped canonical rules
  const filteredRules = useMemo(() => {
    return analytics.allGroupedRules.filter((rule) => {
      const sev = String(rule.severity || '').toUpperCase();
      const st = String(rule.status || '').toUpperCase();
      const cat = String(rule.category || '');

      const matchesSev = severityFilter === 'ALL' || sev === severityFilter;
      const matchesSt = statusFilter === 'ALL' || st === statusFilter;
      const matchesCat = categoryFilter === 'ALL' || cat === categoryFilter;

      const term = searchTerm.toLowerCase().trim();
      const matchesSearch =
        !term ||
        rule.title?.toLowerCase().includes(term) ||
        rule.description?.toLowerCase().includes(term) ||
        rule.ruleId?.toLowerCase().includes(term);

      return matchesSev && matchesSt && matchesCat && matchesSearch;
    });
  }, [analytics.allGroupedRules, severityFilter, statusFilter, categoryFilter, searchTerm]);

  if (loading) {
    return (
      <LoadingState
        title="RFC & Compliance Audit"
        message="Evaluating 19 RFC security rules, deductions, and CVE/CWE alignments..."
      />
    );
  }

  if (!report || !session) {
    return (
      <EmptyAnalysisState
        title="START ANALYSIS"
        description="Run an analysis to generate verified findings."
        buttonText="Start Analysis"
        featureBadge="RFC & Vulnerability Audit"
      />
    );
  }

  return (
    <div className="relative min-h-screen bg-[#F7F7F5] px-6 py-8 lg:px-10">
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
              className="inline-flex items-center gap-2 rounded-xl bg-[#111111] px-4 py-2.5 text-xs font-bold text-white shadow-sm transition hover:bg-[#222222]"
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

        {/* Master Metrics Grid */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
          <div className="rounded-2xl border border-[#E5E5E0] bg-white p-4 shadow-sm">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">19 Canonical Rules</span>
            <p className="mt-1 text-2xl font-black text-[#111111]">{CANONICAL_RULES_COUNT}</p>
            <span className="text-[10px] text-neutral-400 font-mono">In scope</span>
          </div>
          <div className="rounded-2xl border border-[#E5E5E0] bg-white p-4 shadow-sm">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">Total Findings</span>
            <p className="mt-1 text-2xl font-black text-[#111111]">{analytics.totalFindings}</p>
            <span className="text-[10px] text-neutral-400 font-mono">Finding instances</span>
          </div>
          <div className="rounded-2xl border border-rose-200 bg-rose-50/50 p-4 shadow-sm">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-rose-700">Violated Rules</span>
            <p className="mt-1 text-2xl font-black text-rose-800">{analytics.uniqueViolatedRulesCount}</p>
            <span className="text-[10px] text-rose-600 font-mono">Unique canonical rules</span>
          </div>
          <div className="rounded-2xl border border-red-200 bg-red-50/50 p-4 shadow-sm">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-red-600">Critical</span>
            <p className="mt-1 text-2xl font-black text-red-700">{analytics.severityCounts.CRITICAL}</p>
            <span className="text-[10px] text-red-500 font-mono">High priority</span>
          </div>
          <div className="rounded-2xl border border-orange-200 bg-orange-50/50 p-4 shadow-sm">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-orange-600">High</span>
            <p className="mt-1 text-2xl font-black text-orange-700">{analytics.severityCounts.HIGH}</p>
            <span className="text-[10px] text-orange-500 font-mono">Action required</span>
          </div>
          <div className="rounded-2xl border border-[#202020] bg-[#111111] p-4 shadow-sm text-white">
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#888888]">Applied Deductions</span>
            <p className="mt-1 text-2xl font-black text-rose-400">−{analytics.totalPenalty} pts</p>
            <span className="text-[10px] text-neutral-400 font-mono">{analytics.totalDeductionsCount} penalties</span>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="mt-6 rounded-2xl border border-[#E5E5E0] bg-white p-5 shadow-sm">
          <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-[#888888]" />
              <input
                type="text"
                placeholder="Search findings by rule, title, or keyword..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full rounded-2xl border border-[#E5E5E0] bg-[#F7F7F5] py-2 pl-10 pr-4 text-xs font-medium text-[#111111] outline-none transition focus:border-[#111111] focus:bg-white"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1.5 text-xs font-bold text-[#888888]">
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
                      ? 'border-[#111111] bg-[#111111] text-white'
                      : 'border-[#E5E5E0] bg-white text-[#555555] hover:border-[#111111]'
                  }`}
                >
                  {s === 'ALL' ? 'All' : s}
                </button>
              ))}

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="rounded-xl border border-[#E5E5E0] bg-white px-3 py-1.5 text-xs font-bold text-[#555555] outline-none focus:border-[#111111]"
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
                  className="rounded-xl border border-[#E5E5E0] bg-white px-3 py-1.5 text-xs font-bold text-[#555555] outline-none focus:border-[#111111]"
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
          {filteredRules.length === 0 ? (
            <div className="rounded-2xl border border-[#E5E5E0] bg-white p-12 text-center shadow-sm">
              <ShieldCheck className="mx-auto h-10 w-10 text-emerald-500" />
              <h3 className="mt-3 text-base font-black text-[#111111]">No rules match the current filters</h3>
              <p className="mt-1 text-xs text-[#666666]">Try broadening your search term or filter criteria.</p>
            </div>
          ) : (
            filteredRules.map((rule) => {
              const key = rule.ruleId;
              const isOpen = expanded === key;
              const linkedWeaknesses = mappingsByRuleId.get(rule.ruleId) || [];

              return (
                <div
                  key={key}
                  className="rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm transition hover:border-[#111111]"
                >
                  <button
                    type="button"
                    onClick={() => setExpanded(isOpen ? null : key)}
                    className="w-full text-left"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-extrabold ${severityBadgeClasses(rule.severity)}`}>
                          <span className={`inline-block h-1.5 w-1.5 rounded-full mr-1.5 ${severityDotClasses(rule.severity)}`} />
                          {rule.severity}
                        </span>

                        <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-extrabold ${statusBadgeClasses(rule.status)}`}>
                          {rule.status}
                        </span>

                        <span className="font-mono text-[10px] font-bold text-[#888888]">
                          {rule.ruleId}
                        </span>

                        {rule.category && (
                          <span className="rounded-lg border border-[#E5E5E0] bg-[#F7F7F5] px-2 py-0.5 text-[10px] font-bold text-[#666666]">
                            {rule.category}
                          </span>
                        )}

                        <span className="rounded-lg border border-[#E5E5E0] bg-[#F7F7F5] px-2 py-0.5 text-[10px] font-bold text-[#444444] font-mono">
                          {rule.instances.length} {rule.instances.length === 1 ? 'evidence instance' : 'evidence instances'}
                        </span>

                        {rule.penaltyApplied > 0 && (
                          <span className="rounded-lg border border-rose-200 bg-rose-50 px-2 py-0.5 text-[10px] font-bold text-rose-700 font-mono">
                            −{rule.penaltyApplied} pts applied
                          </span>
                        )}
                      </div>

                      <ChevronDown
                        className={`h-5 w-5 shrink-0 text-[#888888] transition-transform ${isOpen ? 'rotate-180 text-[#111111]' : ''}`}
                      />
                    </div>

                    <h3 className="mt-3 text-base font-black text-[#111111]">{rule.title}</h3>
                    <p className="mt-1 text-xs leading-5 text-[#555555]">{rule.description}</p>
                  </button>

                  {/* Expanded Detail Panel */}
                  {isOpen && (
                    <div className="mt-5 border-t border-[#E5E5E0] pt-5 space-y-4">
                      {/* Actionable Remediation Guidance */}
                      {rule.recommendation && (
                        <div className="rounded-2xl border border-[#E5E5E0] bg-[#F7F7F5] p-4">
                          <p className="text-[10px] font-bold uppercase tracking-wider text-[#111111]">Actionable Remediation Guidance</p>
                          <p className="mt-1 text-xs leading-5 font-semibold text-[#222222]">{rule.recommendation}</p>
                        </div>
                      )}

                      {/* Supporting Finding & Evidence Instances */}
                      <div className="rounded-2xl border border-slate-200 bg-slate-50/70 p-4 space-y-3">
                        <div className="flex items-center justify-between">
                          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                            Supporting Forensic Evidence ({rule.instances.length} {rule.instances.length === 1 ? 'Instance' : 'Instances'})
                          </p>
                          <span className="text-[10px] font-mono text-slate-400">RFC Conformance Verification</span>
                        </div>

                        <div className="space-y-2.5">
                          {rule.instances.map((instance, idx) => (
                            <div key={instance.finding_id || idx} className="rounded-xl border border-slate-200 bg-white p-3.5 shadow-2xs">
                              <div className="flex items-center justify-between border-b border-slate-100 pb-2 mb-2">
                                <span className="font-mono text-[11px] font-bold text-slate-700">
                                  {instance.finding_id || `Instance #${idx + 1}`}
                                </span>
                                <span className="text-[10px] font-mono text-slate-500">
                                  {instance.evidence?.stream_id ? `Stream: ${String(instance.evidence.stream_id).slice(0, 18)}` : 'Session Anchor'}
                                  {instance.evidence?.packet_number && ` · Frame #${instance.evidence.packet_number}`}
                                </span>
                              </div>

                              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 text-xs font-mono">
                                <div>
                                  <span className="text-[9px] uppercase text-slate-400 block">Observed Property</span>
                                  <span className="font-semibold text-slate-800 break-words">{valueOrUnavailable(instance.evidence?.observed_property)}</span>
                                </div>
                                <div>
                                  <span className="text-[9px] uppercase text-slate-400 block">Observed Value</span>
                                  <span className="font-semibold text-slate-900 break-words">{valueOrUnavailable(instance.evidence?.observed_value)}</span>
                                </div>
                                <div>
                                  <span className="text-[9px] uppercase text-slate-400 block">Expected Reference</span>
                                  <span className="font-semibold text-slate-700 break-words">{valueOrUnavailable(instance.evidence?.reference_value, 'Standard baseline')}</span>
                                </div>
                              </div>
                            </div>
                          ))}
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
                        <span>Standard: 19 Canonical RFC Rules · Calibrated Posture Budget</span>
                        <span className="font-mono">{rule.ruleId}</span>
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
