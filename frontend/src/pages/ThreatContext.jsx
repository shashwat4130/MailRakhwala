import React, { useState, useMemo } from 'react';
import {
  Dna,
  ShieldAlert,
  AlertTriangle,
  ExternalLink,
  Search,
  Filter,
  Layers,
  ArrowRight,
  Info,
} from 'lucide-react';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { LoadingState } from '../components/LoadingScreen';
import { safeVal } from '../utils/formatters';

export default function ThreatContext() {
  const { report, loading, error, reload, analysisId } = useAnalysis();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [expandedThreat, setExpandedThreat] = useState(null);

  const threats = report?.threat_mappings || [];

  // Available categories
  const availableCategories = useMemo(() => {
    const cats = new Set(threats.map((t) => t.category).filter(Boolean));
    return Array.from(cats);
  }, [threats]);

  // Filtered threats
  const filteredThreats = useMemo(() => {
    return threats.filter((t) => {
      const matchCategory = selectedCategory === 'ALL' || t.category === selectedCategory;
      const term = searchTerm.toLowerCase();
      const matchSearch =
        !term ||
        t.title?.toLowerCase().includes(term) ||
        t.description?.toLowerCase().includes(term) ||
        t.mitre_attack?.technique_id?.toLowerCase().includes(term) ||
        t.mitre_attack?.technique_name?.toLowerCase().includes(term) ||
        t.cwe_id?.toLowerCase().includes(term) ||
        t.upstream_finding_id?.toLowerCase().includes(term);

      return matchCategory && matchSearch;
    });
  }, [threats, selectedCategory, searchTerm]);

  if (!analysisId) {
    return <EmptyAnalysisState title="Threat Context" />;
  }

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <PageHeader
        category="INTELLIGENCE"
        title="Threat Context"
        description="Evidence-backed correlation linking passive cryptographic weaknesses to MITRE ATT&CK adversarial techniques and known exploitation vectors."
        onRefresh={reload}
        isRefreshing={loading}
      />

      {loading && !report ? (
        <LoadingState
          title="Threat Context Mapping"
          message="Correlating observed weaknesses with MITRE ATT&CK adversarial techniques..."
        />
      ) : error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50/50 p-6 text-red-700">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-6 w-6 text-red-600" />
            <span className="font-semibold">Failed to load threat context</span>
          </div>
          <p className="mt-2 text-sm text-red-600">{error}</p>
        </div>
      ) : threats.length === 0 ? (
        <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-slate-100 text-slate-500">
            <Dna className="h-6 w-6" />
          </div>
          <h3 className="mt-4 text-base font-bold text-slate-900">
            No Threat Context Mappings Identified
          </h3>
          <p className="mt-1 text-xs text-slate-500 max-w-md mx-auto">
            No observed cryptographic weaknesses or protocol violations in this capture met the criteria
            for MITRE ATT&CK adversarial correlation.
          </p>
        </div>
      ) : (
        <>
          {/* Controls: Search and Filter */}
          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search by ATT&CK ID (e.g. T1040), technique name, CWE..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-4 py-2 text-xs rounded-xl border border-slate-200 bg-white focus:outline-none focus:ring-2 focus:ring-[#111111]/20 focus:border-[#111111]"
              />
            </div>

            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-slate-400 shrink-0" />
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                className="text-xs rounded-xl border border-slate-200 bg-white px-3 py-2 text-slate-700 focus:outline-none focus:ring-2 focus:ring-[#111111]/20 focus:border-[#111111]"
              >
                <option value="ALL">All Categories ({threats.length})</option>
                {availableCategories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat.replace(/_/g, ' ')}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Threat Cards */}
          <div className="space-y-4">
            {filteredThreats.length === 0 ? (
              <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center text-slate-500 text-sm">
                No threat context entries match the filter criteria.
              </div>
            ) : (
              filteredThreats.map((threat) => {
                const isExpanded = expandedThreat === threat.threat_mapping_id;
                const mitre = threat.mitre_attack;

                return (
                  <div
                    key={threat.threat_mapping_id}
                    className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm hover:border-[#111111] transition-all"
                  >
                    <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                      <div className="space-y-2 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          {mitre?.technique_id && (
                            <span className="font-mono text-xs font-black text-rose-700 bg-rose-50 border border-rose-200/60 px-2.5 py-0.5 rounded-md">
                              ATT&CK {mitre.technique_id}
                            </span>
                          )}
                          <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
                            {safeVal(threat.category, 'GENERAL').replace(/_/g, ' ')}
                          </span>
                          <span className="text-xs font-semibold text-[#111111] bg-[#F7F7F5] border border-[#E5E5E0] px-2 py-0.5 rounded">
                            {threat.status}
                          </span>
                          {threat.cwe_id && (
                            <span className="font-mono text-xs text-amber-800 bg-amber-50 px-2 py-0.5 rounded">
                              {threat.cwe_id}
                            </span>
                          )}
                          {threat.cve_id && (
                            <span className="font-mono text-xs text-red-800 bg-red-50 px-2 py-0.5 rounded">
                              {threat.cve_id}
                            </span>
                          )}
                        </div>

                        <h3 className="text-base font-bold text-slate-900">
                          {mitre?.technique_name ? `${mitre.technique_name} — ` : ''}
                          {threat.title}
                        </h3>

                        <p className="text-xs text-slate-600 leading-relaxed max-w-4xl">
                          {threat.description}
                        </p>

                        {/* MITRE Tactic & Upstream Link */}
                        <div className="flex items-center gap-4 text-xs text-slate-500 pt-1">
                          {mitre?.tactic && (
                            <span>
                              Primary Tactic: <strong className="text-slate-800">{mitre.tactic}</strong>
                            </span>
                          )}
                          <span>
                            Upstream Finding: <strong className="text-[#111111] font-mono">{threat.upstream_finding_id}</strong>
                          </span>
                        </div>
                      </div>

                      {/* Right Action: External MITRE link & details toggle */}
                      <div className="flex items-center gap-2 shrink-0">
                        {mitre?.url && (
                          <a
                            href={mitre.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#555555] hover:text-[#111111] bg-[#F7F7F5] hover:bg-white px-3 py-1.5 rounded-lg border border-[#E5E5E0] transition-colors"
                          >
                            MITRE Reference
                            <ExternalLink className="h-3.5 w-3.5" />
                          </a>
                        )}

                        <button
                          onClick={() => setExpandedThreat(isExpanded ? null : threat.threat_mapping_id)}
                          className="text-xs font-semibold text-[#111111] hover:text-black flex items-center gap-1 px-3 py-1.5 rounded-lg bg-[#F7F7F5] border border-[#E5E5E0] hover:bg-white transition-colors"
                        >
                          {isExpanded ? 'Hide Traceability' : 'Trace Evidence'}
                          <ArrowRight className={`h-3.5 w-3.5 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                        </button>
                      </div>
                    </div>

                    {/* Expandable Traceability Drawer */}
                    {isExpanded && (
                      <div className="mt-4 pt-4 border-t border-slate-100 bg-slate-50/70 rounded-xl p-4 text-xs space-y-3">
                        <div className="font-semibold text-slate-800 uppercase tracking-wider text-[10px]">
                          Forensic Telemetry Linkage
                        </div>

                        {threat.evidence && (
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-slate-700">
                            <div>
                              <span className="text-slate-400 block text-[11px]">Observed Property</span>
                              <span className="font-mono font-medium">{threat.evidence.observed_property}</span>
                            </div>
                            <div>
                              <span className="text-slate-400 block text-[11px]">Observed Value</span>
                              <span className="font-mono font-bold text-slate-900">{String(threat.evidence.observed_value)}</span>
                            </div>
                            <div>
                              <span className="text-slate-400 block text-[11px]">Source Component</span>
                              <span className="font-mono">{threat.evidence.source_component}</span>
                            </div>
                          </div>
                        )}

                        {threat.limitations && (
                          <div className="text-[11px] text-slate-500 pt-2 border-t border-slate-200">
                            <span className="font-semibold text-slate-600">Limitations: </span>
                            {threat.limitations}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>

          {/* Context Boundary Disclaimer */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-4 text-xs text-slate-600 leading-relaxed flex items-start gap-3">
            <Info className="h-5 w-5 text-slate-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-slate-700">Threat Context Disclaimer:</span> This view maps
              observable configuration deficiencies to standard MITRE ATT&CK technique classifications.
              It represents architectural relevance and adversarial context — NOT real-time intrusion alerts or
              evidence of active execution on your network.
            </div>
          </div>
        </>
      )}
    </div>
  );
}
