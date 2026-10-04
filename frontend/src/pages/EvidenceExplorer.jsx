import React, { useMemo, useState } from 'react';
import {
  Search,
  Filter,
  FileText,
  Layers,
  Terminal,
  ChevronDown,
  RefreshCw,
  ExternalLink,
  Code2,
  X,
} from 'lucide-react';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { LoadingState } from '../components/LoadingScreen';
import { valueOrUnavailable, formatTimestamp } from '../utils/formatters';
import { severityBadgeClasses } from '../utils/severity';

export default function EvidenceExplorer() {
  const { report, loading } = useAnalysis();

  const [searchTerm, setSearchTerm] = useState('');
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [selectedEvidence, setSelectedEvidence] = useState(null);

  // Normalize all evidence across findings, posture deductions, weaknesses, and threats
  const allEvidence = useMemo(() => {
    if (!report) return [];
    const items = [];

    // 1. Compliance Findings Evidence
    const findings = Array.isArray(report.compliance_findings) ? report.compliance_findings : [];
    findings.forEach((f) => {
      if (f.evidence) {
        items.push({
          id: `finding-${f.finding_id}`,
          sourceType: 'Compliance Finding',
          ruleId: f.rule_id || f.evidence.rule_id,
          title: f.title,
          severity: f.severity,
          observedProperty: f.evidence.observed_property,
          observedValue: f.evidence.observed_value,
          referenceValue: f.evidence.reference_value,
          streamId: f.evidence.stream_id,
          packetNumber: f.evidence.packet_number,
          timestamp: f.evidence.timestamp,
          sourceComponent: f.evidence.source_component || 'PCAP_OBSERVATION',
          raw: f,
        });
      }
    });

    // 2. Posture Deductions Evidence
    const deductions = Array.isArray(report.posture_report?.deductions) ? report.posture_report.deductions : [];
    deductions.forEach((d, idx) => {
      items.push({
        id: `deduction-${d.rule_id}-${idx}`,
        sourceType: 'Posture Deduction',
        ruleId: d.rule_id,
        title: d.title,
        severity: d.severity || (d.penalty >= 15 ? 'CRITICAL' : d.penalty >= 10 ? 'HIGH' : d.penalty >= 5 ? 'MEDIUM' : 'LOW'),
        penalty: d.penalty,
        observedProperty: d.observed_property,
        observedValue: d.observed_value,
        referenceValue: 'Base Cryptographic Policy',
        streamId: d.stream_id,
        packetNumber: null,
        timestamp: null,
        sourceComponent: 'POSTURE_ENGINE',
        raw: d,
      });
    });

    // 3. Vulnerability Mappings Evidence
    const weaknesses = Array.isArray(report.vulnerability_mappings) ? report.vulnerability_mappings : [];
    weaknesses.forEach((w) => {
      if (w.evidence) {
        items.push({
          id: `weakness-${w.mapping_id}`,
          sourceType: 'Weakness Mapping',
          ruleId: w.identifier || w.source_rule_id,
          title: w.title,
          severity: 'HIGH',
          observedProperty: w.evidence.observed_property,
          observedValue: w.evidence.observed_value,
          referenceValue: w.evidence.reference_value,
          streamId: w.evidence.stream_id,
          packetNumber: w.evidence.packet_number,
          timestamp: w.evidence.timestamp,
          sourceComponent: 'VULNERABILITY_MAPPING',
          raw: w,
        });
      }
    });

    // 4. Threat Mappings Evidence
    const threats = Array.isArray(report.threat_mappings) ? report.threat_mappings : [];
    threats.forEach((t) => {
      if (t.evidence) {
        items.push({
          id: `threat-${t.threat_mapping_id}`,
          sourceType: 'Threat Context',
          ruleId: t.rule_id,
          title: t.title,
          severity: t.status === 'CONFIRMED_FROM_EVIDENCE' ? 'CRITICAL' : 'MEDIUM',
          observedProperty: t.evidence.observed_property,
          observedValue: t.evidence.observed_value,
          referenceValue: t.evidence.reference_value,
          streamId: t.evidence.stream_id,
          packetNumber: t.evidence.packet_number,
          timestamp: t.evidence.timestamp,
          sourceComponent: t.evidence.source_component || 'THREAT_MAPPING',
          raw: t,
        });
      }
    });

    return items;
  }, [report]);

  const filteredEvidence = useMemo(() => {
    return allEvidence.filter((item) => {
      const matchesSource = sourceFilter === 'ALL' || item.sourceType === sourceFilter;
      const term = searchTerm.toLowerCase().trim();
      const matchesSearch =
        !term ||
        item.ruleId.toLowerCase().includes(term) ||
        item.title.toLowerCase().includes(term) ||
        String(item.observedProperty).toLowerCase().includes(term) ||
        String(item.observedValue).toLowerCase().includes(term) ||
        String(item.streamId).toLowerCase().includes(term);

      return matchesSource && matchesSearch;
    });
  }, [allEvidence, sourceFilter, searchTerm]);

  if (loading) {
    return (
      <LoadingState
        title="Forensic Evidence Telemetry"
        message="Gathering packet traces, stream offsets, and cryptographic proof records..."
      />
    );
  }

  if (!report || !report.session) {
    return (
      <EmptyAnalysisState
        title="START ANALYSIS"
        description="Run an analysis to explore evidence."
        buttonText="Start Analysis"
        featureBadge="Evidence Records"
      />
    );
  }

  return (
    <div className="relative min-h-screen bg-[#F7F7F5] px-6 py-8 lg:px-10">
      <div className="relative z-10 mx-auto max-w-[1400px]">
        <PageHeader
          category="Traceable Telemetry"
          title="Evidence Explorer"
          description="Direct index of observable network telemetry, packet anchors, and values substantiating all security evaluations."
          session={report.session}
        />

        {/* Filter and Search Bar */}
        <div className="mb-6 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-[#888888]" />
            <input
              type="text"
              placeholder="Search by rule, property, value, or stream..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full rounded-2xl border border-[#E5E5E0] bg-white py-2.5 pl-10 pr-4 text-xs font-medium text-[#111111] shadow-sm outline-none transition focus:border-[#111111]"
            />
          </div>

          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-[#888888]" />
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="rounded-2xl border border-[#E5E5E0] bg-white px-3 py-2.5 text-xs font-bold text-[#555555] shadow-sm outline-none focus:border-[#111111]"
            >
              <option value="ALL">All Evidence Sources ({allEvidence.length})</option>
              <option value="Compliance Finding">Compliance Findings</option>
              <option value="Posture Deduction">Posture Deductions</option>
              <option value="Weakness Mapping">Weakness Mappings</option>
              <option value="Threat Context">Threat Context</option>
            </select>
          </div>
        </div>

        {/* Evidence Table */}
        <div className="overflow-hidden rounded-2xl border border-[#E5E5E0] bg-white shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#E5E5E0] bg-[#F7F7F5] text-[10px] font-extrabold uppercase tracking-wider text-[#888888]">
                <tr>
                  <th className="py-3.5 pl-6 pr-3">Rule / ID</th>
                  <th className="px-3 py-3.5">Source Type</th>
                  <th className="px-3 py-3.5">Observed Property</th>
                  <th className="px-3 py-3.5">Observed Value</th>
                  <th className="px-3 py-3.5">Stream Anchor</th>
                  <th className="px-3 py-3.5">Packet / Time</th>
                  <th className="py-3.5 pl-3 pr-6 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E5E0]">
                {filteredEvidence.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-xs text-[#666666]">
                      No evidence records match the search criteria.
                    </td>
                  </tr>
                ) : (
                  filteredEvidence.map((item) => (
                    <tr
                      key={item.id}
                      onClick={() => setSelectedEvidence(item)}
                      className="cursor-pointer transition hover:bg-[#F7F7F5]"
                    >
                      <td className="py-3.5 pl-6 pr-3 font-mono font-bold text-[#111111]">
                        {item.ruleId}
                        <p className="font-sans font-normal text-[11px] text-[#666666] line-clamp-1">{item.title}</p>
                      </td>
                      <td className="px-3 py-3.5 whitespace-nowrap">
                        <span className="rounded-lg border border-[#E5E5E0] bg-[#F7F7F5] px-2 py-0.5 text-[10px] font-bold text-[#555555]">
                          {item.sourceType}
                        </span>
                      </td>
                      <td className="px-3 py-3.5 font-mono text-[#555555]">
                        {valueOrUnavailable(item.observedProperty)}
                      </td>
                      <td className="px-3 py-3.5 font-mono font-bold text-[#111111] max-w-[200px] truncate">
                        {valueOrUnavailable(item.observedValue)}
                      </td>
                      <td className="px-3 py-3.5 font-mono text-[11px] text-[#666666] max-w-[160px] truncate">
                        {valueOrUnavailable(item.streamId, 'Session')}
                      </td>
                      <td className="px-3 py-3.5 whitespace-nowrap font-mono text-[11px] text-[#666666]">
                        {item.packetNumber ? `Frame #${item.packetNumber}` : 'Frame unanchored'}
                        {item.timestamp && <p className="text-[10px] text-[#888888]">{formatTimestamp(item.timestamp)}</p>}
                      </td>
                      <td className="py-3.5 pl-3 pr-6 text-right">
                        <button
                          type="button"
                          className="rounded-lg border border-[#E5E5E0] bg-[#F7F7F5] px-2.5 py-1 text-[11px] font-bold text-[#111111] transition hover:bg-[#111111] hover:text-white"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Evidence Modal / Detail Drawer */}
        {selectedEvidence && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
            <div className="w-full max-w-2xl rounded-2xl border border-[#202020] bg-white p-6 shadow-2xl">
              <div className="flex items-start justify-between border-b border-[#E5E5E0] pb-4">
                <div>
                  <span className="rounded-md border border-[#E5E5E0] bg-[#F7F7F5] px-2 py-0.5 text-[10px] font-bold text-[#111111]">
                    {selectedEvidence.sourceType}
                  </span>
                  <h3 className="mt-1.5 text-lg font-black text-[#111111]">{selectedEvidence.title}</h3>
                  <p className="font-mono text-xs text-[#888888]">{selectedEvidence.ruleId}</p>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedEvidence(null)}
                  className="rounded-xl p-2 text-[#888888] hover:bg-[#F7F7F5]"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              <div className="mt-5 space-y-4 text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-xl border border-slate-100 bg-slate-50 p-3">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Observed Property</p>
                    <p className="mt-1 font-mono font-bold text-slate-900">{valueOrUnavailable(selectedEvidence.observedProperty)}</p>
                  </div>
                  <div className="rounded-xl border border-slate-100 bg-slate-50 p-3">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Source Component</p>
                    <p className="mt-1 font-mono font-bold text-slate-900">{selectedEvidence.sourceComponent}</p>
                  </div>
                </div>

                <div className="rounded-xl border border-slate-100 bg-slate-50 p-3">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Observed Telemetry Value</p>
                  <pre className="mt-1 whitespace-pre-wrap break-words font-mono text-xs leading-5 text-slate-900">
                    {valueOrUnavailable(selectedEvidence.observedValue)}
                  </pre>
                </div>

                <div className="rounded-xl border border-slate-100 bg-slate-50 p-3">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Reference / Expected Value</p>
                  <pre className="mt-1 whitespace-pre-wrap break-words font-mono text-xs leading-5 text-slate-700">
                    {valueOrUnavailable(selectedEvidence.referenceValue, 'Standard normative baseline')}
                  </pre>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-xl border border-slate-100 bg-slate-50 p-3">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Stream Anchor</p>
                    <p className="mt-1 font-mono text-slate-800 break-words">{valueOrUnavailable(selectedEvidence.streamId)}</p>
                  </div>
                  <div className="rounded-xl border border-slate-100 bg-slate-50 p-3">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Frame / Timestamp</p>
                    <p className="mt-1 font-mono text-slate-800">
                      {selectedEvidence.packetNumber ? `Frame #${selectedEvidence.packetNumber}` : 'Frame unanchored'} · {formatTimestamp(selectedEvidence.timestamp)}
                    </p>
                  </div>
                </div>
              </div>

              <div className="mt-6 flex justify-end">
                <button
                  type="button"
                  onClick={() => setSelectedEvidence(null)}
                  className="rounded-xl bg-slate-900 px-5 py-2.5 text-xs font-bold text-white hover:bg-slate-800"
                >
                  Close Inspection
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
