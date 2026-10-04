import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  MinusCircle,
  CheckCircle2,
  HelpCircle,
  Layers,
  Search,
  ArrowDownRight,
  Shield,
  FileText,
  Filter,
  ArrowRight,
  Info,
} from 'lucide-react';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { getSeverityBadge, getScoreColor, getStatusBadge } from '../utils/severity';
import { safeVal } from '../utils/formatters';
import {
  getPostureScore,
  hasEmailProtocol,
  isReportApplicable,
  getAssessmentStatus,
  getApplicabilityReason,
} from '../utils/reportModel';

export default function SecurityPosture() {
  const { report, loading, error, reload, analysisId } = useAnalysis();

  // Deductions search state
  const [deductionSearch, setDeductionSearch] = useState('');
  const [selectedDeduction, setSelectedDeduction] = useState(null);

  // Evaluated rules state
  const [ruleSearch, setRuleSearch] = useState('');
  const [ruleStatus, setRuleStatus] = useState('ALL');
  const [ruleCategory, setRuleCategory] = useState('ALL');
  const [expandedRule, setExpandedRule] = useState(null);

  const posture = report?.posture_report;
  const deductions = posture?.deductions || [];
  const findings = report?.compliance_findings || [];
  const isApplicable = isReportApplicable(report);
  const score = getPostureScore(report);
  const scoreColors = getScoreColor(score ?? 0);

  // Deductions filtering
  const filteredDeductions = useMemo(() => {
    if (!deductionSearch) return deductions;
    const term = deductionSearch.toLowerCase();
    return deductions.filter(
      (d) =>
        d.title?.toLowerCase().includes(term) ||
        d.rule_id?.toLowerCase().includes(term) ||
        d.finding_id?.toLowerCase().includes(term) ||
        d.observed_property?.toLowerCase().includes(term)
    );
  }, [deductions, deductionSearch]);

  // Evaluated rules unique statuses & categories
  const availableStatuses = useMemo(() => {
    const statuses = new Set(findings.map((f) => f.status).filter(Boolean));
    return Array.from(statuses);
  }, [findings]);

  const availableCategories = useMemo(() => {
    const cats = new Set(findings.map((f) => f.category).filter(Boolean));
    return Array.from(cats);
  }, [findings]);

  // Evaluated rules filtering
  const filteredRules = useMemo(() => {
    return findings.filter((f) => {
      const matchStatus = ruleStatus === 'ALL' || f.status === ruleStatus;
      const matchCategory = ruleCategory === 'ALL' || f.category === ruleCategory;
      const term = ruleSearch.toLowerCase();
      const matchSearch =
        !term ||
        f.rule_id?.toLowerCase().includes(term) ||
        f.title?.toLowerCase().includes(term) ||
        f.description?.toLowerCase().includes(term) ||
        f.evidence?.observed_property?.toLowerCase().includes(term);

      return matchStatus && matchCategory && matchSearch;
    });
  }, [findings, ruleStatus, ruleCategory, ruleSearch]);

  if (!analysisId) {
    return <EmptyAnalysisState title="Security Posture" />;
  }

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <PageHeader
        category="SECURITY"
        title="Security Posture"
        description="Deterministic 0-100 cryptographic posture score derived from passive RFC conformance audits with transparent penalty waterfalls and evaluated rule catalog."
        onRefresh={reload}
        isRefreshing={loading}
      />

      {loading && !report ? (
        <div className="flex h-64 items-center justify-center rounded-2xl border border-blue-100 bg-white/70 shadow-sm">
          <div className="flex items-center gap-3 text-slate-500">
            <Shield className="h-6 w-6 animate-spin text-blue-600" />
            <span className="text-sm font-medium">Computing posture audit & rule evaluations...</span>
          </div>
        </div>
      ) : error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50/50 p-6 text-red-700">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-6 w-6 text-red-600" />
            <span className="font-semibold">Failed to load posture report</span>
          </div>
          <p className="mt-2 text-sm text-red-600">{error}</p>
        </div>
      ) : !posture ? (
        <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-slate-500">
          No cryptographic posture report found for this session.
        </div>
      ) : (
        <>
          {/* Truthful Non-Email Distinction Banner */}
          {!isApplicable ? (
            <div className="rounded-2xl border border-amber-200 bg-amber-50/90 p-5 shadow-sm flex items-start gap-3.5">
              <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0 mt-0.5" />
              <div className="text-xs text-amber-900 leading-relaxed">
                <span className="font-bold text-amber-950 block text-sm mb-0.5">
                  Assessment Not Applicable: Non-Email Capture
                </span>
                No supported email protocol/security assessment was observed in this capture. Email RFC compliance rules were not evaluated. No email security posture was calculated.
              </div>
            </div>
          ) : null}

          {/* Top Metric & Score Overview */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Primary Score Card */}
            <div className="rounded-2xl border border-slate-200 bg-gradient-to-br from-white via-slate-50/40 to-slate-100/30 p-6 shadow-sm flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs uppercase font-extrabold tracking-wider text-slate-500">
                    Cryptographic Posture Score
                  </span>
                  <span
                    className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                      isApplicable ? getSeverityBadge(posture.severity).badge : 'bg-slate-100 text-slate-700 border border-slate-200'
                    }`}
                  >
                    {isApplicable ? (posture.severity || 'UNKNOWN') : 'NOT APPLICABLE'} RISK
                  </span>
                </div>

                <div className="mt-4 flex items-baseline gap-3">
                  <span className={`text-6xl font-black tracking-tight ${isApplicable && score !== null ? scoreColors.text : 'text-slate-400'}`}>
                    {isApplicable && score !== null ? score : 'N/A'}
                  </span>
                  <span className="text-xl font-bold text-slate-400">/ 100</span>
                </div>

                {/* Progress bar */}
                <div className="mt-4 h-3 w-full rounded-full bg-slate-200 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      !isApplicable || score === null
                        ? 'bg-slate-300'
                        : score >= 80
                        ? 'bg-emerald-500'
                        : score >= 60
                        ? 'bg-blue-500'
                        : score >= 30
                        ? 'bg-amber-500'
                        : 'bg-red-500'
                    }`}
                    style={{ width: `${isApplicable && score !== null ? Math.max(3, Math.min(100, score)) : 0}%` }}
                  />
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
                <span>Base Score: <strong className="text-slate-800">{isApplicable ? `${posture.base_score ?? 100} pts` : 'N/A'}</strong></span>
                <span>Total Deductions: <strong className={isApplicable ? 'text-rose-600' : 'text-slate-500'}>{isApplicable ? `-${posture.total_penalty ?? 0} pts` : '0 pts'}</strong></span>
              </div>
            </div>

            {/* Finding Evaluation Breakdown */}
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
              <div>
                <span className="text-xs uppercase font-extrabold tracking-wider text-slate-500">
                  Compliance Findings Evaluated
                </span>
                <div className="mt-4 text-3xl font-black text-slate-900">
                  {isApplicable ? (posture.evaluated_findings_count ?? findings.length) : 0}
                </div>
                <p className="text-xs text-slate-500 mt-1">
                  Deterministic RFC rule checks across captured streams
                </p>

                <div className="mt-4 space-y-2.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-1.5 text-emerald-700 font-medium">
                      <CheckCircle2 className="h-3.5 w-3.5" /> Compliant
                    </span>
                    <span className="font-bold text-slate-900">
                      {posture.compliant_findings_count ?? 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-1.5 text-rose-700 font-medium">
                      <MinusCircle className="h-3.5 w-3.5" /> Non-Compliant
                    </span>
                    <span className="font-bold text-slate-900">
                      {posture.non_compliant_findings_count ?? 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-1.5 text-slate-500 font-medium">
                      <HelpCircle className="h-3.5 w-3.5" /> Unknown / Missing Evidence
                    </span>
                    <span className="font-bold text-slate-900">
                      {posture.unknown_findings_count ?? 0}
                    </span>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-400">
                100% deterministic; calculated strictly from observable parameters
              </div>
            </div>

            {/* Audit Engine Metadata */}
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
              <div>
                <span className="text-xs uppercase font-extrabold tracking-wider text-slate-500">
                  Engine & Methodology
                </span>

                <div className="mt-4 space-y-3 text-xs">
                  <div>
                    <span className="text-slate-400 block">Evaluation Mode</span>
                    <span className="font-semibold text-slate-800 flex items-center gap-1.5 mt-0.5">
                      <ShieldCheck className="h-3.5 w-3.5 text-blue-600" />
                      {posture.deterministic ? 'Deterministic RFC Conformance' : 'Statistical'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Engine Version</span>
                    <span className="font-mono font-semibold text-slate-800">
                      v{posture.engine_version || '1.0.0'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Session ID</span>
                    <span className="font-mono text-slate-600 truncate block">
                      {safeVal(posture.session_id, 'N/A')}
                    </span>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-500 leading-relaxed">
                {safeVal(
                  posture.limitations,
                  'Deterministic evaluation of passive network traffic. Not an attack likelihood model.'
                )}
              </div>
            </div>
          </div>

          {/* Interactive Deductions Waterfall */}
          <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            <div className="border-b border-slate-100 bg-slate-50/75 p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <Layers className="h-5 w-5 text-blue-600" />
                  <h3 className="text-base font-bold text-slate-900">
                    Transparent Deduction Waterfall
                  </h3>
                  <span className="rounded-full bg-rose-100 px-2 py-0.5 text-xs font-bold text-rose-700">
                    {deductions.length} Applied
                  </span>
                </div>
                <p className="text-xs text-slate-500 mt-1">
                  Each penalty represents a verified non-compliant condition deducted from the 100-point base score.
                </p>
              </div>

              {/* Search deductions */}
              <div className="relative w-full sm:w-64">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Filter deductions..."
                  value={deductionSearch}
                  onChange={(e) => setDeductionSearch(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                />
              </div>
            </div>

            {filteredDeductions.length === 0 ? (
              <div className="p-12 text-center text-slate-500 text-sm">
                {deductions.length === 0
                  ? (isEmail ? 'Zero deductions applied. Cryptographic posture reflects optimal RFC conformance.' : 'No deductions evaluated for this non-email capture.')
                  : 'No deductions match your search filter.'}
              </div>
            ) : (
              <div className="divide-y divide-slate-100">
                {filteredDeductions.map((d, index) => (
                  <div
                    key={`${d.rule_id}-${index}`}
                    className="p-5 hover:bg-slate-50/60 transition-colors cursor-pointer"
                    onClick={() => setSelectedDeduction(selectedDeduction === d ? null : d)}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-3">
                        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-rose-50 text-rose-600 font-mono text-xs font-bold mt-0.5">
                          -{d.penalty}
                        </div>
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-xs font-bold text-blue-700 bg-blue-50 px-2 py-0.5 rounded">
                              {d.rule_id}
                            </span>
                            <h4 className="text-sm font-bold text-slate-900">{d.title}</h4>
                            <span className="text-[11px] font-mono text-slate-400">
                              (Finding: {d.finding_id})
                            </span>
                          </div>
                          <p className="mt-1 text-xs text-slate-600 leading-relaxed">
                            {d.description}
                          </p>

                          {/* Quick evidence pills */}
                          <div className="mt-2.5 flex items-center gap-2 flex-wrap text-[11px]">
                            <span className="bg-slate-100 text-slate-700 px-2 py-0.5 rounded font-mono">
                              Property: <strong className="text-slate-900">{d.observed_property}</strong>
                            </span>
                            <span className="bg-rose-50 text-rose-800 px-2 py-0.5 rounded font-mono">
                              Observed: <strong className="text-rose-900">{String(d.observed_value)}</strong>
                            </span>
                            {d.stream_id && (
                              <span className="bg-slate-100 text-slate-600 px-2 py-0.5 rounded font-mono">
                                Stream: {d.stream_id}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="shrink-0 flex items-center gap-2">
                        <span className="text-xs font-bold text-rose-600 font-mono">
                          -{d.penalty} pts
                        </span>
                        <ArrowDownRight className="h-4 w-4 text-slate-400" />
                      </div>
                    </div>

                    {/* Detailed drawer when clicked */}
                    {selectedDeduction === d && (
                      <div className="mt-4 pt-4 border-t border-slate-200/80 bg-slate-50/80 rounded-xl p-4 text-xs space-y-2">
                        <div className="font-semibold text-slate-800 uppercase tracking-wider text-[10px]">
                          Complete Traceability Details
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-slate-700">
                          <div>
                            <span className="text-slate-400 block text-[11px]">Upstream Compliance Rule</span>
                            <span className="font-mono font-medium">{d.upstream_rule_id}</span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[11px]">Compliance Finding Reference</span>
                            <span className="font-mono font-medium">{d.finding_id}</span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[11px]">Observed Property</span>
                            <span className="font-mono font-medium">{d.observed_property}</span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[11px]">Observed Telemetry Value</span>
                            <span className="font-mono font-bold text-rose-700">{String(d.observed_value)}</span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Evaluated Compliance Rules Section (Consolidated from SecurityRules) */}
          <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            <div className="border-b border-slate-100 bg-slate-50/75 p-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <Shield className="h-5 w-5 text-blue-600" />
                    <h3 className="text-base font-bold text-slate-900">
                      Evaluated Security Rules Catalog
                    </h3>
                    <span className="rounded-full bg-blue-100 text-blue-800 px-2 py-0.5 text-xs font-bold">
                      {findings.length} Evaluated
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-1">
                    Every RFC compliance rule evaluated against captured protocol handshakes and observable cryptographic parameters.
                  </p>
                </div>

                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                  {/* Search */}
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
                    <input
                      type="text"
                      placeholder="Search rules, properties..."
                      value={ruleSearch}
                      onChange={(e) => setRuleSearch(e.target.value)}
                      className="w-full sm:w-56 pl-9 pr-3 py-1.5 text-xs rounded-xl border border-slate-200 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                    />
                  </div>

                  {/* Category filter */}
                  {availableCategories.length > 0 && (
                    <div className="flex items-center gap-1.5">
                      <Filter className="h-3.5 w-3.5 text-slate-400 shrink-0" />
                      <select
                        value={ruleCategory}
                        onChange={(e) => setRuleCategory(e.target.value)}
                        className="text-xs rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                      >
                        <option value="ALL">All Categories</option>
                        {availableCategories.map((cat) => (
                          <option key={cat} value={cat}>
                            {cat.replace(/_/g, ' ')}
                          </option>
                        ))}
                      </select>
                    </div>
                  )}
                </div>
              </div>

              {/* Status Filter Pills */}
              {availableStatuses.length > 0 && (
                <div className="flex items-center gap-2 overflow-x-auto pt-4 text-xs">
                  <span className="text-slate-400 font-medium shrink-0 text-[11px] uppercase tracking-wider">
                    Status:
                  </span>
                  <button
                    onClick={() => setRuleStatus('ALL')}
                    className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors shrink-0 ${
                      ruleStatus === 'ALL'
                        ? 'bg-blue-600 text-white'
                        : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                    }`}
                  >
                    All ({findings.length})
                  </button>

                  {availableStatuses.map((st) => {
                    const count = findings.filter((f) => f.status === st).length;
                    const isSelected = ruleStatus === st;
                    return (
                      <button
                        key={st}
                        onClick={() => setRuleStatus(st)}
                        className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors shrink-0 ${
                          isSelected
                            ? 'bg-slate-900 text-white'
                            : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                        }`}
                      >
                        {st.replace(/_/g, ' ')} ({count})
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Rules List */}
            {filteredRules.length === 0 ? (
              <div className="p-12 text-center text-slate-500 text-sm">
                {findings.length === 0
                  ? 'No security rules evaluated for this session.'
                  : 'No rules match the selected filter criteria.'}
              </div>
            ) : (
              <div className="divide-y divide-slate-100">
                {filteredRules.map((rule) => {
                  const isExpanded = expandedRule === (rule.finding_id || rule.rule_id);
                  const statusInfo = getStatusBadge(rule.status);
                  const sevInfo = getSeverityBadge(rule.severity);

                  return (
                    <div key={rule.finding_id || rule.rule_id} className="p-6 hover:bg-slate-50/50 transition-colors">
                      <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                        <div className="space-y-2 flex-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-xs font-bold text-blue-700 bg-blue-50 px-2.5 py-0.5 rounded-md border border-blue-200/50">
                              {rule.rule_id}
                            </span>
                            <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
                              {safeVal(rule.category, 'GENERAL').replace(/_/g, ' ')}
                            </span>
                            <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${statusInfo.badge}`}>
                              {rule.status}
                            </span>
                            <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${sevInfo.badge}`}>
                              {rule.severity}
                            </span>
                          </div>

                          <h4 className="text-base font-bold text-slate-900">{rule.title}</h4>
                          <p className="text-xs text-slate-600 leading-relaxed max-w-4xl">
                            {rule.description}
                          </p>

                          {/* Observed Evidence Telemetry */}
                          {rule.evidence && (
                            <div className="flex items-center gap-2 flex-wrap pt-1 text-xs">
                              <span className="bg-slate-100 text-slate-700 px-2 py-0.5 rounded font-mono text-[11px]">
                                Property: <strong className="text-slate-900">{rule.evidence.observed_property}</strong>
                              </span>
                              <span className="bg-slate-100 text-slate-700 px-2 py-0.5 rounded font-mono text-[11px]">
                                Observed: <strong className="text-blue-900">{safeVal(rule.evidence.observed_value, 'None')}</strong>
                              </span>
                              {rule.evidence.reference_value && (
                                <span className="bg-emerald-50 text-emerald-800 px-2 py-0.5 rounded font-mono text-[11px]">
                                  Expected: <strong className="text-emerald-900">{String(rule.evidence.reference_value)}</strong>
                                </span>
                              )}
                            </div>
                          )}
                        </div>

                        <button
                          onClick={() => setExpandedRule(isExpanded ? null : (rule.finding_id || rule.rule_id))}
                          className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1 shrink-0 self-start"
                        >
                          {isExpanded ? 'Hide Guidance' : 'View Recommendation'}
                          <ArrowRight className={`h-3.5 w-3.5 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                        </button>
                      </div>

                      {/* Expandable Guidance Drawer */}
                      {isExpanded && (
                        <div className="mt-4 pt-4 border-t border-slate-200/80 bg-slate-50/70 rounded-xl p-4 text-xs space-y-3">
                          {rule.recommendation && (
                            <div>
                              <span className="font-semibold text-slate-800 uppercase tracking-wider text-[10px] block mb-1">
                                Actionable Recommendation
                              </span>
                              <p className="text-slate-700 leading-relaxed bg-white p-3 rounded-lg border border-slate-200">
                                {rule.recommendation}
                              </p>
                            </div>
                          )}

                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-slate-600 pt-1 text-[11px]">
                            <div>
                              <span className="text-slate-400 block">Finding ID</span>
                              <span className="font-mono text-slate-800 font-medium">{rule.finding_id}</span>
                            </div>
                            <div>
                              <span className="text-slate-400 block">Stream ID</span>
                              <span className="font-mono text-slate-800 font-medium">{rule.evidence?.stream_id || 'N/A'}</span>
                            </div>
                            <div>
                              <span className="text-slate-400 block">Engine Mode</span>
                              <span className="font-mono text-slate-800 font-medium">Deterministic Conformance</span>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
