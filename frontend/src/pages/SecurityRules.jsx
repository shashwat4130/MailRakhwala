import React, { useState, useMemo } from 'react';
import {
  Shield,
  CheckCircle2,
  AlertTriangle,
  MinusCircle,
  HelpCircle,
  Search,
  Filter,
  ArrowRight,
  BookOpen,
} from 'lucide-react';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { getStatusBadge, getSeverityBadge } from '../utils/severity';
import { safeVal } from '../utils/formatters';

export default function SecurityRules() {
  const { report, loading, error, reload, analysisId } = useAnalysis();
  const [selectedStatus, setSelectedStatus] = useState('ALL');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedRule, setExpandedRule] = useState(null);

  const findings = report?.compliance_findings || [];

  // Extract unique statuses and categories present in actual data
  const availableStatuses = useMemo(() => {
    const statuses = new Set(findings.map((f) => f.status).filter(Boolean));
    return Array.from(statuses);
  }, [findings]);

  const availableCategories = useMemo(() => {
    const cats = new Set(findings.map((f) => f.category).filter(Boolean));
    return Array.from(cats);
  }, [findings]);

  // Filter rules
  const filteredRules = useMemo(() => {
    return findings.filter((f) => {
      const matchStatus = selectedStatus === 'ALL' || f.status === selectedStatus;
      const matchCategory = selectedCategory === 'ALL' || f.category === selectedCategory;
      const term = searchTerm.toLowerCase();
      const matchSearch =
        !term ||
        f.rule_id?.toLowerCase().includes(term) ||
        f.title?.toLowerCase().includes(term) ||
        f.description?.toLowerCase().includes(term) ||
        f.evidence?.observed_property?.toLowerCase().includes(term);

      return matchStatus && matchCategory && matchSearch;
    });
  }, [findings, selectedStatus, selectedCategory, searchTerm]);

  if (!analysisId) {
    return <EmptyAnalysisState title="Security Rules" />;
  }

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <PageHeader
        category="SECURITY"
        title="Security Rules"
        description="Authoritative catalog of RFC compliance rules evaluated against observed email protocol sessions and cryptographic handshakes."
        onRefresh={reload}
        isRefreshing={loading}
      />

      {loading && !report ? (
        <div className="flex h-64 items-center justify-center rounded-2xl border border-blue-100 bg-white/70 shadow-sm">
          <div className="flex items-center gap-3 text-slate-500">
            <Shield className="h-6 w-6 animate-spin text-blue-600" />
            <span className="text-sm font-medium">Evaluating RFC security rules...</span>
          </div>
        </div>
      ) : error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50/50 p-6 text-red-700">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-6 w-6 text-red-600" />
            <span className="font-semibold">Failed to load security rules</span>
          </div>
          <p className="mt-2 text-sm text-red-600">{error}</p>
        </div>
      ) : findings.length === 0 ? (
        <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-slate-500">
          No security rules or compliance findings found for this session.
        </div>
      ) : (
        <>
          {/* Controls & Filter Bar */}
          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              {/* Search */}
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search by rule ID (e.g. RULE-TLS-001), title, property..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-9 pr-4 py-2 text-xs rounded-xl border border-slate-200 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                />
              </div>

              {/* Category filter */}
              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4 text-slate-400 shrink-0" />
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="text-xs rounded-xl border border-slate-200 bg-white px-3 py-2 text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                >
                  <option value="ALL">All Categories ({findings.length})</option>
                  {availableCategories.map((cat) => (
                    <option key={cat} value={cat}>
                      {cat.replace(/_/g, ' ')}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Status Pills */}
            <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
              <span className="text-slate-400 font-medium shrink-0 text-[11px] uppercase tracking-wider">
                Status:
              </span>
              <button
                onClick={() => setSelectedStatus('ALL')}
                className={`rounded-lg px-3 py-1 text-xs font-semibold transition-colors shrink-0 ${
                  selectedStatus === 'ALL'
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                All ({findings.length})
              </button>

              {availableStatuses.map((st) => {
                const count = findings.filter((f) => f.status === st).length;
                const isSelected = selectedStatus === st;
                return (
                  <button
                    key={st}
                    onClick={() => setSelectedStatus(st)}
                    className={`rounded-lg px-3 py-1 text-xs font-semibold transition-colors shrink-0 ${
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
          </div>

          {/* Rules List */}
          <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden divide-y divide-slate-100">
            {filteredRules.length === 0 ? (
              <div className="p-12 text-center text-slate-500 text-sm">
                No security rules match the selected criteria.
              </div>
            ) : (
              filteredRules.map((rule) => {
                const isExpanded = expandedRule === rule.rule_id;
                const statusInfo = getStatusBadge(rule.status);
                const sevInfo = getSeverityBadge(rule.severity);

                return (
                  <div key={rule.finding_id || rule.rule_id} className="p-6 hover:bg-slate-50/50 transition-colors">
                    <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                      {/* Left: Info */}
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
                          {rule.deterministic && (
                            <span className="text-[11px] text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded font-medium">
                              Deterministic
                            </span>
                          )}
                        </div>

                        <h3 className="text-base font-bold text-slate-900">{rule.title}</h3>
                        <p className="text-xs text-slate-600 leading-relaxed max-w-4xl">
                          {rule.description}
                        </p>

                        {/* Evidence property chips */}
                        {rule.evidence && (
                          <div className="flex items-center gap-2 flex-wrap pt-1 text-xs">
                            <span className="bg-slate-100 text-slate-700 px-2 py-0.5 rounded font-mono text-[11px]">
                              Observed Property: <strong className="text-slate-900">{rule.evidence.observed_property}</strong>
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

                      {/* Right: Expand action */}
                      <button
                        onClick={() => setExpandedRule(isExpanded ? null : rule.rule_id)}
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
                            <span className="text-slate-400 block">Engine Version</span>
                            <span className="font-mono text-slate-800 font-medium">v{rule.engine_version || '1.0.0'}</span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </>
      )}
    </div>
  );
}
