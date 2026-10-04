import React, { useState, useMemo } from 'react';
import {
  FileText,
  Download,
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  LockKeyhole,
  Network,
  Cpu,
  Layers,
  Dna,
  Bug,
  Brain,
  Printer,
  ChevronRight,
  ExternalLink,
  FileJson,
  FileSpreadsheet,
  RefreshCw,
} from 'lucide-react';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { LoadingState } from '../components/LoadingScreen';
import { downloadAnalysisPdf, downloadAnalysisJson } from '../services/api';
import { getSeverityBadge, getStatusBadge, getScoreColor } from '../utils/severity';
import { formatBytes, formatUtcTimestamp, safeVal, exportToCsv } from '../utils/formatters';
import {
  getPostureScore,
  hasEmailProtocol,
  isReportApplicable,
  getApplicabilityReason,
} from '../utils/reportModel';

const TABS = [
  { id: 'summary', label: 'Executive Summary', icon: Shield },
  { id: 'session', label: 'Session & Scope', icon: Network },
  { id: 'protocol', label: 'Protocol & TLS', icon: LockKeyhole },
  { id: 'posture', label: 'Posture & Deductions', icon: ShieldCheck },
  { id: 'findings', label: 'Compliance Findings', icon: AlertTriangle },
  { id: 'weaknesses', label: 'Vulnerabilities', icon: Bug },
  { id: 'threats', label: 'Threat Context', icon: Dna },
  { id: 'ml', label: 'ML & Anomaly', icon: Brain },
  { id: 'methodology', label: 'Methodology', icon: FileText },
];

export default function Reports() {
  const { report, loading, error, reload, analysisId } = useAnalysis();
  const [activeTab, setActiveTab] = useState('summary');
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [downloadingJson, setDownloadingJson] = useState(false);
  const [exportNotification, setExportNotification] = useState(null);

  const isApplicable = isReportApplicable(report);
  const applicabilityReason =
    getApplicabilityReason(report) ||
    'No supported email protocol/security assessment was observed in this capture.';

  const session = report?.session;
  const protocol = report?.protocol_summary;
  const posture = report?.posture_report;
  const findings = report?.compliance_findings || [];
  const weaknesses = report?.vulnerability_mappings || [];
  const threats = report?.threat_mappings || [];
  const anomaly = report?.anomaly_detection;
  const risk = report?.risk_classification;

  const score = getPostureScore(report);
  const scoreColors = getScoreColor(score ?? 0);
  const isEmail = isApplicable;

  // 1. Download PDF (via backend GET /analysis/{id}/report/pdf)
  const handleDownloadPdf = async () => {
    if (!analysisId) return;
    try {
      setDownloadingPdf(true);
      await downloadAnalysisPdf(analysisId);
      setExportNotification('Formal Executive Audit PDF generated and downloaded successfully.');
    } catch (err) {
      console.error('PDF download error:', err);
      setExportNotification('Failed to generate PDF report. Check backend connectivity.');
    } finally {
      setDownloadingPdf(false);
    }
  };

  // 2. Download JSON (via backend GET /analysis/{id}/report)
  const handleDownloadJson = async () => {
    if (!analysisId) return;
    try {
      setDownloadingJson(true);
      await downloadAnalysisJson(analysisId);
      setExportNotification('Complete machine-readable JSON report downloaded successfully.');
    } catch (err) {
      console.error('JSON download error:', err);
      setExportNotification('Failed to download JSON report.');
    } finally {
      setDownloadingJson(false);
    }
  };

  // 3. Export Findings CSV (RFC 4180 client-side download)
  const handleExportFindingsCsv = () => {
    if (!report?.compliance_findings || report.compliance_findings.length === 0) {
      setExportNotification('No compliance findings available to export.');
      return;
    }
    const rows = report.compliance_findings.map((f) => ({
      finding_id: f.finding_id,
      rule_id: f.rule_id,
      title: f.title,
      category: f.category,
      severity: f.severity,
      status: f.status,
      stream_id: f.evidence?.stream_id || '',
      packet_number: f.evidence?.packet_number ?? '',
      timestamp: f.evidence?.timestamp ?? '',
      observed_property: f.evidence?.observed_property || '',
      observed_value: String(f.evidence?.observed_value ?? ''),
      reference_value: String(f.evidence?.reference_value ?? ''),
      recommendation: f.recommendation || '',
    }));

    exportToCsv(rows, `mailrakhwala-findings-${analysisId.slice(0, 8)}.csv`);
    setExportNotification('Compliance Findings CSV exported successfully.');
  };

  // 4. Export Forensic Evidence CSV (from findings & deductions)
  const handleExportEvidenceCsv = () => {
    if (!report) return;
    const evidenceList = [];

    // Findings evidence
    (report.compliance_findings || []).forEach((f) => {
      if (f.evidence) {
        evidenceList.push({
          source_type: 'Compliance Finding',
          source_id: f.finding_id,
          rule_id: f.rule_id,
          stream_id: f.evidence.stream_id || '',
          packet_number: f.evidence.packet_number ?? '',
          timestamp: f.evidence.timestamp ?? '',
          observed_property: f.evidence.observed_property || '',
          observed_value: String(f.evidence.observed_value ?? ''),
          reference_value: String(f.evidence.reference_value ?? ''),
          source_component: f.evidence.source_component || 'ComplianceEngine',
        });
      }
    });

    // Posture deductions evidence
    (report.posture_report?.deductions || []).forEach((d) => {
      evidenceList.push({
        source_type: 'Posture Deduction',
        source_id: d.finding_id || d.rule_id,
        rule_id: d.upstream_rule_id || d.rule_id,
        stream_id: d.stream_id || '',
        packet_number: '',
        timestamp: '',
        observed_property: d.observed_property || '',
        observed_value: String(d.observed_value ?? ''),
        reference_value: '',
        source_component: 'CryptographicPostureEngine',
      });
    });

    if (evidenceList.length === 0) {
      setExportNotification('No evidence records found in this capture.');
      return;
    }

    exportToCsv(evidenceList, `mailrakhwala-evidence-${analysisId.slice(0, 8)}.csv`);
    setExportNotification('Forensic Evidence Telemetry CSV exported successfully.');
  };

  // 5. Export Posture Deductions CSV
  const handleExportDeductionsCsv = () => {
    if (!report?.posture_report?.deductions || report.posture_report.deductions.length === 0) {
      setExportNotification('No posture deductions applied to this session.');
      return;
    }
    const rows = report.posture_report.deductions.map((d) => ({
      rule_id: d.rule_id,
      title: d.title,
      penalty: d.penalty,
      upstream_rule_id: d.upstream_rule_id,
      finding_id: d.finding_id,
      observed_property: d.observed_property,
      observed_value: String(d.observed_value ?? ''),
      stream_id: d.stream_id || '',
      description: d.description,
    }));

    exportToCsv(rows, `mailrakhwala-deductions-${analysisId.slice(0, 8)}.csv`);
    setExportNotification('Posture Deductions CSV exported successfully.');
  };

  if (!analysisId || !report) {
    return (
      <EmptyAnalysisState
        title="START ANALYSIS"
        description="Run an analysis before generating forensic reports."
        buttonText="Start Analysis"
        featureBadge="Forensic Reporting"
      />
    );
  }

  return (
    <div className="p-6 sm:p-8 max-w-7xl mx-auto space-y-6 bg-[#F7F7F5]">
      <PageHeader
        category="REPORTING"
        title="Forensic Reports"
        description="Audit-ready cryptographic inspection reports and evidence export center supporting PDF, JSON, and CSV exports alongside interactive forensic sections."
        onRefresh={reload}
        isRefreshing={loading}
      />

      {!isApplicable && (
        <div className="rounded-xl border border-amber-200 bg-amber-50/90 p-4 text-xs text-amber-900 flex items-start gap-3 shadow-sm">
          <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0 mt-0.5" />
          <div>
            <span className="font-bold text-sm block mb-0.5">Assessment Not Applicable: Non-Email Capture</span>
            {applicabilityReason} The forensic audit records this capture as not applicable for email security assessment. No email RFC compliance findings or security posture score were evaluated.
          </div>
        </div>
      )}

      {/* Export Notification Banner */}
      {exportNotification && (
        <div className="rounded-xl border border-[#202020] bg-[#111111] p-4 flex items-center justify-between text-xs text-white shadow-sm">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <span className="font-medium">{exportNotification}</span>
          </div>
          <button
            onClick={() => setExportNotification(null)}
            className="text-white/80 font-bold hover:text-white hover:underline shrink-0"
          >
            Dismiss
          </button>
        </div>
      )}

      {loading && !report ? (
        <LoadingState
          variant="page"
          title="Forensic Report Generation"
          message="Compiling executive audit artifacts, cryptographic telemetry, and compliance tables..."
        />
      ) : error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50/50 p-6 text-red-700">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-6 w-6 text-red-600" />
            <span className="font-semibold">Failed to load report</span>
          </div>
          <p className="mt-2 text-sm text-red-600">{error}</p>
        </div>
      ) : (
        <>
          {/* Consolidated Export Action Center */}
          <div className="rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-[#111111]">
                  Forensic Export Center
                </h3>
                <p className="text-xs text-[#666666] mt-0.5">
                  Download executive audit reports and forensic data in formal PDF, machine JSON, and structured CSV formats. Card bodies are informational; use the dedicated download buttons below.
                </p>
              </div>
              <span className="text-xs font-mono bg-[#F7F7F5] border border-[#E5E5E0] text-[#111111] px-2.5 py-1 rounded-lg font-bold">
                5 Export Formats
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 pt-2">
              {/* 1. PDF */}
              <div
                className="flex flex-col justify-between p-4 rounded-xl border border-[#E5E5E0] bg-[#FAFAF8] text-left"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-rose-100 text-rose-700">
                      <FileText className="h-5 w-5" />
                    </div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-rose-700 bg-rose-50 border border-rose-200 px-1.5 py-0.5 rounded">
                      PDF
                    </span>
                  </div>
                  <span className="text-xs font-bold text-[#111111] block">Executive PDF</span>
                  <span className="text-[11px] text-[#666666] mt-0.5 block leading-tight">
                    {downloadingPdf ? 'Generating...' : 'ReportLab Audit PDF'}
                  </span>
                </div>

                <button
                  type="button"
                  aria-label="Download Executive PDF"
                  onClick={handleDownloadPdf}
                  disabled={downloadingPdf || !report}
                  className="w-full mt-3.5 inline-flex items-center justify-center gap-1.5 rounded-xl bg-[#111111] hover:bg-[#222222] active:bg-black text-white text-[11px] font-bold py-2.5 px-3 shadow-sm transition disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-[#111111] focus:ring-offset-1"
                >
                  {downloadingPdf ? (
                    <>
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      <span>Generating...</span>
                    </>
                  ) : (
                    <>
                      <Download className="h-3.5 w-3.5" />
                      <span>Download PDF</span>
                    </>
                  )}
                </button>
              </div>

              {/* 2. JSON */}
              <div
                className="flex flex-col justify-between p-4 rounded-xl border border-[#E5E5E0] bg-[#FAFAF8] text-left"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#111111] text-white">
                      <FileJson className="h-5 w-5" />
                    </div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-neutral-800 bg-neutral-100 border border-neutral-300 px-1.5 py-0.5 rounded">
                      JSON
                    </span>
                  </div>
                  <span className="text-xs font-bold text-[#111111] block">Complete JSON</span>
                  <span className="text-[11px] text-[#666666] mt-0.5 block leading-tight">
                    {downloadingJson ? 'Downloading...' : 'Raw Backend Report'}
                  </span>
                </div>

                <button
                  type="button"
                  aria-label="Download Complete JSON"
                  onClick={handleDownloadJson}
                  disabled={downloadingJson || !report}
                  className="w-full mt-3.5 inline-flex items-center justify-center gap-1.5 rounded-xl bg-[#111111] hover:bg-[#222222] active:bg-black text-white text-[11px] font-bold py-2.5 px-3 shadow-sm transition disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-[#111111] focus:ring-offset-1"
                >
                  {downloadingJson ? (
                    <>
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      <span>Downloading...</span>
                    </>
                  ) : (
                    <>
                      <Download className="h-3.5 w-3.5" />
                      <span>Download JSON</span>
                    </>
                  )}
                </button>
              </div>

              {/* 3. Findings CSV */}
              <div
                className="flex flex-col justify-between p-4 rounded-xl border border-[#E5E5E0] bg-[#FAFAF8] text-left"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-100 text-emerald-700">
                      <FileSpreadsheet className="h-5 w-5" />
                    </div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-800 bg-emerald-50 border border-emerald-200 px-1.5 py-0.5 rounded">
                      CSV
                    </span>
                  </div>
                  <span className="text-xs font-bold text-[#111111] block">Findings CSV</span>
                  <span className="text-[11px] text-[#666666] mt-0.5 block leading-tight">
                    {findings.length} Compliance Records
                  </span>
                </div>

                <button
                  type="button"
                  aria-label="Download Findings CSV"
                  onClick={handleExportFindingsCsv}
                  disabled={!report}
                  className="w-full mt-3.5 inline-flex items-center justify-center gap-1.5 rounded-xl bg-[#111111] hover:bg-[#222222] active:bg-black text-white text-[11px] font-bold py-2.5 px-3 shadow-sm transition disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-[#111111] focus:ring-offset-1"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>Download CSV</span>
                </button>
              </div>

              {/* 4. Evidence CSV */}
              <div
                className="flex flex-col justify-between p-4 rounded-xl border border-[#E5E5E0] bg-[#FAFAF8] text-left"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-purple-100 text-purple-700">
                      <FileSpreadsheet className="h-5 w-5" />
                    </div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-purple-800 bg-purple-50 border border-purple-200 px-1.5 py-0.5 rounded">
                      CSV
                    </span>
                  </div>
                  <span className="text-xs font-bold text-[#111111] block">Evidence CSV</span>
                  <span className="text-[11px] text-[#666666] mt-0.5 block leading-tight">
                    Observed Telemetry
                  </span>
                </div>

                <button
                  type="button"
                  aria-label="Download Evidence CSV"
                  onClick={handleExportEvidenceCsv}
                  disabled={!report}
                  className="w-full mt-3.5 inline-flex items-center justify-center gap-1.5 rounded-xl bg-[#111111] hover:bg-[#222222] active:bg-black text-white text-[11px] font-bold py-2.5 px-3 shadow-sm transition disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-[#111111] focus:ring-offset-1"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>Download CSV</span>
                </button>
              </div>

              {/* 5. Deductions CSV */}
              <div
                className="flex flex-col justify-between p-4 rounded-xl border border-[#E5E5E0] bg-[#FAFAF8] text-left"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-amber-100 text-amber-700">
                      <FileSpreadsheet className="h-5 w-5" />
                    </div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-amber-800 bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded">
                      CSV
                    </span>
                  </div>
                  <span className="text-xs font-bold text-[#111111] block">Deductions CSV</span>
                  <span className="text-[11px] text-[#666666] mt-0.5 block leading-tight">
                    -{posture?.total_penalty ?? 0} Penalty Points
                  </span>
                </div>

                <button
                  type="button"
                  aria-label="Download Deductions CSV"
                  onClick={handleExportDeductionsCsv}
                  disabled={!report}
                  className="w-full mt-3.5 inline-flex items-center justify-center gap-1.5 rounded-xl bg-[#111111] hover:bg-[#222222] active:bg-black text-white text-[11px] font-bold py-2.5 px-3 shadow-sm transition disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-[#111111] focus:ring-offset-1"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>Download CSV</span>
                </button>
              </div>
            </div>
          </div>

          {/* Section Navigation Tabs */}
          <div className="flex items-center gap-1 border-b border-[#E5E5E0] overflow-x-auto pb-1 text-xs">
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              if (tab.id === 'weaknesses' && weaknesses.length === 0) return null;
              if (tab.id === 'threats' && threats.length === 0) return null;

              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-1.5 px-3.5 py-2.5 rounded-t-xl font-bold border-b-2 transition-all shrink-0 ${
                    isActive
                      ? 'border-[#111111] text-[#111111] bg-white shadow-xs'
                      : 'border-transparent text-[#666666] hover:text-[#111111] hover:bg-[#EAEAE8]'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          {/* TAB 1: EXECUTIVE SUMMARY */}
          {activeTab === 'summary' && (
            <div className="space-y-6">
              <div className="rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                  <div className="space-y-2">
                    <span className="text-xs uppercase font-extrabold tracking-wider text-neutral-400">
                      Cryptographic Posture Assessment
                    </span>
                    <h2 className="text-2xl font-black text-[#111111]">
                      Executive Security Verdict
                    </h2>
                    <p className="text-xs text-[#666666] max-w-2xl leading-relaxed">
                      This formal audit provides an evidence-based cryptographic evaluation of network
                      traffic observed in session <span className="font-mono font-bold text-[#111111]">{safeVal(session?.session_id, 'N/A')}</span>.
                      Scoring is calculated strictly from passive protocol evidence and RFC compliance baselines.
                    </p>
                  </div>

                  <div className="flex items-center gap-6 shrink-0 border-t lg:border-t-0 lg:border-l border-[#E5E5E0] pt-4 lg:pt-0 lg:pl-8">
                    <div>
                      <span className="text-xs uppercase font-bold text-neutral-400 block">
                        Posture Score
                      </span>
                      <div className="flex items-baseline gap-1 mt-1">
                        <span className={`text-5xl font-black tracking-tight ${isApplicable && score !== null ? scoreColors.text : 'text-neutral-400'}`}>
                          {isApplicable && score !== null ? score : 'N/A'}
                        </span>
                        <span className="text-lg font-bold text-neutral-400">/ 100</span>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <span className="text-xs uppercase font-bold text-neutral-400 block">
                        Risk Rating
                      </span>
                      <span
                        className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-black uppercase tracking-wider ${
                          isApplicable
                            ? getSeverityBadge(posture?.severity).badge
                            : 'bg-[#F7F7F5] text-neutral-700 border border-[#E5E5E0]'
                        }`}
                      >
                        {isApplicable ? (posture?.severity || 'UNKNOWN') : 'NOT APPLICABLE'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Metric Summary Grid */}
                <div className="mt-8 grid grid-cols-2 md:grid-cols-4 gap-4 pt-6 border-t border-[#F0F0EE] text-xs">
                  <div>
                    <span className="text-neutral-400 block">Identified Protocol</span>
                    <span className="font-bold text-[#111111] text-sm mt-0.5 block">
                      {safeVal(protocol?.detected_protocol, 'Unknown')}
                    </span>
                  </div>
                  <div>
                    <span className="text-neutral-400 block">TLS Evidence</span>
                    <span className="font-bold text-[#111111] text-sm mt-0.5 block">
                      {protocol?.has_tls ? 'Observed / Present' : 'None Detected'}
                    </span>
                  </div>
                  <div>
                    <span className="text-neutral-400 block">Evaluated Rules</span>
                    <span className="font-bold text-[#111111] text-sm mt-0.5 block">
                      {findings.length} Compliance Checks
                    </span>
                  </div>
                  <div>
                    <span className="text-neutral-400 block">Score Deductions</span>
                    <span className="font-bold text-rose-600 text-sm mt-0.5 block">
                      -{posture?.total_penalty ?? 0} Penalty Points
                    </span>
                  </div>
                </div>
              </div>

              {/* Actionable Recommendations Summary */}
              {report?.recommendations && report.recommendations.length > 0 && (
                <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
                  <h3 className="text-base font-bold text-slate-900">
                    High Priority Remediation Recommendations
                  </h3>
                  <div className="divide-y divide-slate-100">
                    {report.recommendations.map((rec, idx) => (
                      <div key={idx} className="py-3 flex items-start gap-3">
                        <span className="font-mono text-xs font-bold text-[#111111] bg-[#F7F7F5] border border-[#E5E5E0] px-2 py-0.5 rounded shrink-0">
                          {rec.rule_id}
                        </span>
                        <div>
                          <h4 className="text-xs font-bold text-slate-900">{rec.title}</h4>
                          <p className="text-xs text-slate-600 mt-0.5 leading-relaxed">
                            {rec.recommendation}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: SESSION & SCOPE */}
          {activeTab === 'session' && (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-6">
              <h3 className="text-base font-bold text-slate-900">Session Execution Parameters</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
                <div className="space-y-3">
                  <div>
                    <span className="text-slate-400 block">Unique Session ID</span>
                    <span className="font-mono font-bold text-slate-800 break-all">{safeVal(session?.session_id, 'N/A')}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Evaluated Capture File</span>
                    <span className="font-medium text-slate-800">{safeVal(session?.filename, 'N/A')}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">File Size</span>
                    <span className="font-medium text-slate-800">{formatBytes(session?.filesize_bytes)}</span>
                  </div>
                </div>

                <div className="space-y-3">
                  <div>
                    <span className="text-slate-400 block">Execution Timestamp</span>
                    <span className="font-medium text-slate-800">{formatUtcTimestamp(session?.created_at)}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Capture Execution Status</span>
                    <span className="inline-flex items-center px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 font-bold">
                      {safeVal(session?.status, 'COMPLETED')}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Total TCP Streams Evaluated</span>
                    <span className="font-bold text-slate-900">{session?.total_streams ?? 1}</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: PROTOCOL & TLS */}
          {activeTab === 'protocol' && (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-6">
              <h3 className="text-base font-bold text-slate-900">Protocol & Cryptographic Parameters</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
                  <span className="text-slate-400 block text-[11px]">Protocol</span>
                  <span className="font-bold text-slate-800 text-sm mt-0.5 block">{safeVal(protocol?.detected_protocol, 'Unknown')}</span>
                </div>
                <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
                  <span className="text-slate-400 block text-[11px]">TLS Version</span>
                  <span className="font-bold text-slate-800 text-sm mt-0.5 block">{safeVal(protocol?.tls_version, 'Unavailable')}</span>
                </div>
                <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
                  <span className="text-slate-400 block text-[11px]">Cipher Suite</span>
                  <span className="font-mono text-slate-800 font-bold text-xs mt-0.5 block truncate">{safeVal(protocol?.cipher_suite, 'Unavailable')}</span>
                </div>
                <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
                  <span className="text-slate-400 block text-[11px]">Key Exchange</span>
                  <span className="font-medium text-slate-800 mt-0.5 block">{safeVal(protocol?.key_exchange, 'Unavailable')}</span>
                </div>
                <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
                  <span className="text-slate-400 block text-[11px]">Forward Secrecy (PFS)</span>
                  <span className="font-bold text-slate-800 mt-0.5 block">{protocol?.perfect_forward_secrecy ? 'Enabled' : 'Disabled'}</span>
                </div>
                <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
                  <span className="text-slate-400 block text-[11px]">STARTTLS Status</span>
                  <span className="font-medium text-slate-800 mt-0.5 block">{safeVal(protocol?.starttls_status, 'Unavailable')}</span>
                </div>
                <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
                  <span className="text-slate-400 block text-[11px]">Certificate Validity</span>
                  <span className="font-medium text-slate-800 mt-0.5 block">{safeVal(protocol?.certificate_validity, 'Unavailable')}</span>
                </div>
                <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
                  <span className="text-slate-400 block text-[11px]">Key Size</span>
                  <span className="font-medium text-slate-800 mt-0.5 block">{protocol?.certificate_key_size ? `${protocol.certificate_key_size} bits` : 'Unavailable'}</span>
                </div>
                <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
                  <span className="text-slate-400 block text-[11px]">Trust Validation</span>
                  <span className="font-medium text-slate-800 mt-0.5 block">{safeVal(protocol?.trust_validation, 'Unavailable')}</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: POSTURE & DEDUCTIONS */}
          {activeTab === 'posture' && (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-slate-900">Score Deduction Waterfall</h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Transparent accounting of all points deducted from the 100-point baseline score
                  </p>
                </div>
                <span className="font-mono text-xs font-bold text-rose-600 bg-rose-50 px-2.5 py-1 rounded">
                  Total Penalty: -{posture?.total_penalty ?? 0} pts
                </span>
              </div>

              {posture?.deductions && posture.deductions.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-200 bg-slate-50 font-semibold text-slate-600">
                      <tr>
                        <th className="py-2.5 px-4">Rule</th>
                        <th className="py-2.5 px-4">Title</th>
                        <th className="py-2.5 px-4">Observed Property</th>
                        <th className="py-2.5 px-4">Observed Value</th>
                        <th className="py-2.5 px-4 text-right">Penalty</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {posture.deductions.map((d, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/60">
                          <td className="py-2.5 px-4 font-mono font-bold text-[#111111]">{d.rule_id}</td>
                          <td className="py-2.5 px-4 font-medium text-slate-900">{d.title}</td>
                          <td className="py-2.5 px-4 font-mono text-slate-600">{d.observed_property}</td>
                          <td className="py-2.5 px-4 font-mono font-bold text-rose-700">{String(d.observed_value)}</td>
                          <td className="py-2.5 px-4 text-right font-mono font-bold text-rose-600">-{d.penalty} pts</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-8 text-center text-slate-400 text-xs">
                  Zero deductions applied. Conformance is optimal.
                </div>
              )}
            </div>
          )}

          {/* TAB 5: COMPLIANCE FINDINGS */}
          {activeTab === 'findings' && (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
              <h3 className="text-base font-bold text-slate-900">
                Compliance Findings Catalog ({findings.length})
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-200 bg-slate-50 font-semibold text-slate-600">
                    <tr>
                      <th className="py-2.5 px-4">Rule ID</th>
                      <th className="py-2.5 px-4">Title</th>
                      <th className="py-2.5 px-4">Category</th>
                      <th className="py-2.5 px-4">Severity</th>
                      <th className="py-2.5 px-4">Status</th>
                      <th className="py-2.5 px-4">Observed Telemetry</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {findings.map((f, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/60">
                        <td className="py-2.5 px-4 font-mono font-bold text-[#111111]">{f.rule_id}</td>
                        <td className="py-2.5 px-4 font-medium text-slate-900">{f.title}</td>
                        <td className="py-2.5 px-4 text-slate-500">{safeVal(f.category, 'General').replace(/_/g, ' ')}</td>
                        <td className="py-2.5 px-4">
                          <span className={`inline-flex px-2 py-0.5 rounded-full text-[11px] font-semibold ${getSeverityBadge(f.severity).badge}`}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-4">
                          <span className={`inline-flex px-2 py-0.5 rounded-full text-[11px] font-semibold ${getStatusBadge(f.status).badge}`}>
                            {f.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 font-mono text-slate-700">
                          {f.evidence ? `${f.evidence.observed_property}: ${String(f.evidence.observed_value)}` : 'None'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 6: VULNERABILITIES */}
          {activeTab === 'weaknesses' && weaknesses.length > 0 && (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
              <h3 className="text-base font-bold text-slate-900">
                Cryptographic Weaknesses & Vulnerabilities ({weaknesses.length})
              </h3>
              <div className="space-y-3">
                {weaknesses.map((w) => (
                  <div key={w.mapping_id} className="p-4 rounded-xl border border-slate-100 bg-slate-50/50 space-y-1 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-amber-700 bg-amber-50 px-2 py-0.5 rounded">
                        {w.identifier}
                      </span>
                      {w.vulnerability_id && (
                        <span className="font-mono font-bold text-red-700 bg-red-50 px-2 py-0.5 rounded">
                          {w.vulnerability_id}
                        </span>
                      )}
                      <h4 className="font-bold text-slate-900">{w.title}</h4>
                    </div>
                    <p className="text-slate-600 mt-1 leading-relaxed">{w.description}</p>
                    <div className="pt-2 flex items-center gap-3 text-slate-400 text-[11px]">
                      <span>Source Rule: <strong className="text-slate-700 font-mono">{w.source_rule_id}</strong></span>
                      <span>Confidence: <strong className="text-slate-700">{w.confidence}</strong></span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 7: THREAT CONTEXT */}
          {activeTab === 'threats' && threats.length > 0 && (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
              <h3 className="text-base font-bold text-slate-900">
                Threat Context Mappings ({threats.length})
              </h3>
              <div className="space-y-3">
                {threats.map((t) => (
                  <div key={t.threat_mapping_id} className="p-4 rounded-xl border border-slate-100 bg-slate-50/50 space-y-1 text-xs">
                    <div className="flex items-center gap-2">
                      {t.mitre_attack?.technique_id && (
                        <span className="font-mono font-bold text-rose-700 bg-rose-50 px-2 py-0.5 rounded">
                          ATT&CK {t.mitre_attack.technique_id}
                        </span>
                      )}
                      <h4 className="font-bold text-slate-900">{t.title}</h4>
                    </div>
                    <p className="text-slate-600 mt-1 leading-relaxed">{t.description}</p>
                    <div className="pt-2 text-slate-400 text-[11px]">
                      Upstream Finding: <strong className="text-slate-700 font-mono">{t.upstream_finding_id}</strong>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 8: ML & ANOMALY */}
          {activeTab === 'ml' && (
            <div className="space-y-6">
              <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
                <h3 className="text-base font-bold text-slate-900">Machine Learning Diagnostics</h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
                    <span className="text-slate-400 block text-[11px]">Isolation Forest Anomaly</span>
                    <div className="mt-1 font-bold text-sm text-slate-900">
                      {anomaly ? (anomaly.is_anomalous ? 'Statistical Outlier (-1)' : 'Normal Pattern (+1)') : 'Model Not Fitted'}
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1">
                      {anomaly?.status_text || 'Unsupervised outlier detection was not active for this run.'}
                    </p>
                  </div>

                  <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
                    <span className="text-slate-400 block text-[11px]">XGBoost Risk Classification</span>
                    <div className="mt-1 font-bold text-sm text-slate-900">
                      {risk?.predicted_class ? `${risk.predicted_class} Predicted` : 'Model Not Fitted'}
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1">
                      {risk?.status_text || 'Supervised risk classification was not evaluated for this capture.'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 9: METHODOLOGY */}
          {activeTab === 'methodology' && (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4 text-xs leading-relaxed text-slate-600">
              <h3 className="text-base font-bold text-slate-900">Authoritative Audit Methodology</h3>
              <p>
                {report?.methodology_disclaimer || (
                  "Cryptographic Security Scores and Compliance Findings are derived deterministically from RFC compliance policies and PKI specifications. ML Risk Classifications reflect XGBoost model probabilities and do not represent empirical attack frequencies. Anomaly Detection flags statistical outliers relative to reference distributions. SHAP attributions indicate mathematical feature contributions toward model prediction."
                )}
              </p>
              <div className="pt-4 border-t border-slate-100 space-y-2">
                <span className="font-bold text-slate-800 block text-xs">Governing Conformance Standards</span>
                <ul className="list-disc pl-5 space-y-1">
                  <li><strong>RFC 8314:</strong> Cleartext Considered Obsolete: Use of Transport Layer Security (TLS) for Email Submission and Access</li>
                  <li><strong>RFC 3207:</strong> SMTP Service Extension for Secure SMTP over Transport Layer Security</li>
                  <li><strong>RFC 7525:</strong> Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)</li>
                  <li><strong>NIST SP 800-52r2:</strong> Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations</li>
                </ul>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}