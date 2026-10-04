import React, { useState } from 'react';
import {
  Download,
  FileJson,
  FileSpreadsheet,
  FileText,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Layers,
  ArrowRight,
} from 'lucide-react';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { exportToCsv, downloadJson } from '../utils/formatters';
import { downloadAnalysisPdf } from '../services/api';

export default function ExportEvidence() {
  const { report, loading, reload, analysisId } = useAnalysis();
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [exportedStatus, setExportedStatus] = useState(null);

  if (!analysisId) {
    return <EmptyAnalysisState title="Export Evidence" />;
  }

  // 1. Export Full JSON
  const handleExportJson = () => {
    if (!report) return;
    const filename = `mailrakhwala-report-${analysisId.slice(0, 8)}.json`;
    downloadJson(report, filename);
    setExportedStatus('Complete JSON Report exported successfully.');
  };

  // 2. Export Findings CSV
  const handleExportFindingsCsv = () => {
    if (!report?.compliance_findings) return;
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
    setExportedStatus('Compliance Findings CSV exported successfully.');
  };

  // 3. Export Telemetry Evidence CSV
  const handleExportEvidenceCsv = () => {
    if (!report) return;
    const evidenceList = [];

    // Extract from findings
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

    // Extract from deductions
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

    exportToCsv(evidenceList, `mailrakhwala-evidence-${analysisId.slice(0, 8)}.csv`);
    setExportedStatus('Evidence Telemetry CSV exported successfully.');
  };

  // 4. Export Posture Deductions CSV
  const handleExportDeductionsCsv = () => {
    if (!report?.posture_report?.deductions) return;
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
    setExportedStatus('Posture Deductions CSV exported successfully.');
  };

  // 5. Download Backend PDF
  const handleDownloadPdf = async () => {
    try {
      setDownloadingPdf(true);
      await downloadAnalysisPdf(analysisId);
      setExportedStatus('Formal PDF Executive Audit Report generated and downloaded.');
    } catch (err) {
      console.error('PDF export failed:', err);
      setExportedStatus('Failed to download PDF report. Ensure backend server is responsive.');
    } finally {
      setDownloadingPdf(false);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <PageHeader
        category="REPORTING"
        title="Export Evidence"
        description="Client-side cryptographic data export and evidence extraction center supporting raw JSON, tabular CSV, and executive PDF reports."
        onRefresh={reload}
        isRefreshing={loading}
      />

      {/* Success / Status notification banner */}
      {exportedStatus && (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50/70 p-4 flex items-center justify-between text-xs text-emerald-800">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-600" />
            <span>{exportedStatus}</span>
          </div>
          <button
            onClick={() => setExportedStatus(null)}
            className="text-emerald-700 font-bold hover:underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Export Options Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Option 1: Complete JSON Report */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-50 text-blue-600">
                <FileJson className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900">Complete JSON Report</h3>
                <span className="text-[11px] font-mono text-slate-400">RFC 8259 Standard JSON</span>
              </div>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Downloads the complete, unaltered machine-readable audit report containing session metadata,
              protocol summaries, deterministic findings, posture deductions, weakness mappings, and ML vectors.
            </p>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between">
            <span className="text-xs text-slate-400">100% Client-side export</span>
            <button
              onClick={handleExportJson}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 text-white text-xs font-semibold hover:bg-blue-700 shadow-sm transition-all"
            >
              <Download className="h-4 w-4" /> Download JSON
            </button>
          </div>
        </div>

        {/* Option 2: Executive PDF Report */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-rose-50 text-rose-600">
                <FileText className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900">Forensic Audit Report (PDF)</h3>
                <span className="text-[11px] font-mono text-slate-400">Backend ReportLab Generator</span>
              </div>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Generates an executive, audit-ready PDF document including cryptographic posture scorecards,
              non-compliant rule breakdowns, certificate validation tables, and actionable remediation steps.
            </p>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between">
            <span className="text-xs text-slate-400">Compiled by backend engine</span>
            <button
              onClick={handleDownloadPdf}
              disabled={downloadingPdf}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 text-white text-xs font-semibold hover:bg-slate-800 shadow-sm transition-all disabled:opacity-50"
            >
              <Download className="h-4 w-4" />
              {downloadingPdf ? 'Generating PDF...' : 'Download PDF'}
            </button>
          </div>
        </div>

        {/* Option 3: Compliance Findings CSV */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-50 text-emerald-600">
                <FileSpreadsheet className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900">Compliance Findings (CSV)</h3>
                <span className="text-[11px] font-mono text-slate-400">
                  {report?.compliance_findings?.length ?? 0} Records
                </span>
              </div>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Export all evaluated compliance rules, observed properties, severity classifications, and
              remediation recommendations formatted for spreadsheet and SIEM analysis.
            </p>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between">
            <span className="text-xs text-slate-400">Properly escaped RFC 4180 CSV</span>
            <button
              onClick={handleExportFindingsCsv}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-600 text-white text-xs font-semibold hover:bg-emerald-700 shadow-sm transition-all"
            >
              <Download className="h-4 w-4" /> Export Findings CSV
            </button>
          </div>
        </div>

        {/* Option 4: Evidence Telemetry CSV */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-purple-50 text-purple-600">
                <FileSpreadsheet className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900">Evidence Telemetry (CSV)</h3>
                <span className="text-[11px] font-mono text-slate-400">Extracted Observed Properties</span>
              </div>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Export all forensic evidence points, packet numbers, timestamps, and observed network telemetry
              values captured across findings and posture deductions.
            </p>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between">
            <span className="text-xs text-slate-400">Multi-component evidence records</span>
            <button
              onClick={handleExportEvidenceCsv}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-purple-600 text-white text-xs font-semibold hover:bg-purple-700 shadow-sm transition-all"
            >
              <Download className="h-4 w-4" /> Export Evidence CSV
            </button>
          </div>
        </div>

        {/* Option 5: Posture Deductions CSV */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-50 text-amber-600">
                <FileSpreadsheet className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900">Posture Deductions (CSV)</h3>
                <span className="text-[11px] font-mono text-slate-400">
                  {report?.posture_report?.deductions?.length ?? 0} Penalty Points
                </span>
              </div>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Export the complete score penalty breakdown detailing point deductions, triggered rules,
              and non-compliant cryptographic parameters.
            </p>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between">
            <span className="text-xs text-slate-400">Transparent deduction waterfall</span>
            <button
              onClick={handleExportDeductionsCsv}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-amber-600 text-white text-xs font-semibold hover:bg-amber-700 shadow-sm transition-all"
            >
              <Download className="h-4 w-4" /> Export Deductions CSV
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
