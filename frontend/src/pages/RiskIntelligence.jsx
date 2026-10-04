import React, { useState, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Compass,
  AlertTriangle,
  CheckCircle2,
  ShieldCheck,
  Brain,
  ScanSearch,
  Activity,
  FileSearch,
  Dna,
  Bug,
  Info,
  Layers,
  Cpu,
  Hash,
  Scale,
  Search,
  Filter,
  ArrowRight,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
  ExternalLink,
  ShieldAlert,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Cell,
  ReferenceLine,
} from 'recharts';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { LoadingState } from '../components/LoadingScreen';
import { getSeverityBadge } from '../utils/severity';
import { safeVal } from '../utils/formatters';
import {
  getCanonicalFeatures,
  getAnomalyDetection,
  getRiskClassification,
  getShapExplanation,
  getPostureScore,
  hasEmailProtocol,
  isReportApplicable,
  getAssessmentStatus,
  getApplicabilityReason,
  getComplianceFindings,
  getPostureDeductions,
  getAuthoritativeStarttlsFinding,
  getAuthoritativeStarttlsDeduction,
  getReportAnalytics,
  CANONICAL_RULES_COUNT,
} from '../utils/reportModel';

const RISK_CLASS_COLORS = {
  LOW: '#10b981',      // Emerald
  MEDIUM: '#f59e0b',   // Amber
  HIGH: '#f97316',     // Orange
  CRITICAL: '#ef4444', // Red
};

const SECTIONS = [
  { id: 'overview', label: 'Dual-Engine Overview', icon: Scale },
  { id: 'anomaly', label: 'Anomaly Detection', icon: ScanSearch },
  { id: 'feature-vector', label: '19D Feature Vector', icon: Hash },
  { id: 'shap', label: 'ML Explainability (SHAP)', icon: Brain },
  { id: 'threats', label: 'Threat Context (ATT&CK)', icon: Dna },
  { id: 'vulnerabilities', label: 'Vulnerabilities (CWE/CVE)', icon: Bug },
];

export default function RiskIntelligence() {
  const { report, loading, error, reload, analysisId } = useAnalysis();
  const [searchParams, setSearchParams] = useSearchParams();

  const activeTab = searchParams.get('tab') || 'overview';
  const setActiveTab = (tabId) => {
    setSearchParams({ tab: tabId });
  };

  // State for Threat Context tab
  const [threatSearch, setThreatSearch] = useState('');
  const [threatCategory, setThreatCategory] = useState('ALL');
  const [expandedThreat, setExpandedThreat] = useState(null);

  // State for Vulnerabilities tab
  const [vulnSearch, setVulnSearch] = useState('');
  const [expandedVuln, setExpandedVuln] = useState(null);

  // Type-safe report model getters
  const isApplicable = isReportApplicable(report);
  const applicabilityReason =
    getApplicabilityReason(report) ||
    'No supported email protocol/security assessment was observed in this capture.';
  const risk = useMemo(() => getRiskClassification(report), [report]);
  const anomaly = useMemo(() => getAnomalyDetection(report), [report]);
  const shap = useMemo(() => getShapExplanation(report), [report]);
  const canonicalFeatures = useMemo(() => getCanonicalFeatures(report), [report]);
  const postureScore = getPostureScore(report);
  const posture = report?.posture_report;
  const analytics = useMemo(() => getReportAnalytics(report), [report]);
  const findings = useMemo(() => getComplianceFindings(report), [report]);
  const deductions = useMemo(() => getPostureDeductions(report), [report]);
  const threats = report?.threat_mappings || [];
  const vulnerabilities = report?.vulnerability_mappings || [];
  const isEmail = isApplicable;

  // Authoritative non-compliant findings list for Engine A
  const authoritativeFindings = useMemo(() => {
    if (!isApplicable) return [];
    return findings.filter((f) => f.status === 'NON_COMPLIANT');
  }, [findings, isApplicable]);

  const evaluatedFindingsCount = isApplicable
    ? (posture?.evaluated_findings_count ?? findings.length)
    : 0;

  // Detect STARTTLS authoritative finding / deduction
  const authStarttlsFinding = useMemo(() => getAuthoritativeStarttlsFinding(report), [report]);
  const authStarttlsDeduction = useMemo(() => getAuthoritativeStarttlsDeduction(report), [report]);

  // Identify any vector mismatches
  const vectorMismatches = useMemo(() => {
    return canonicalFeatures.filter((f) => f.mismatch);
  }, [canonicalFeatures]);

  // Authoritative availability flags
  const isMlRiskAvailable = isApplicable && risk && risk.available !== false && Boolean(risk.predicted_class);
  const isAnomalyAvailable = anomaly && anomaly.available !== false && anomaly.is_anomalous !== null && typeof anomaly.anomaly_score === 'number';
  const isShapAvailable = shap && shap.available !== false && Boolean(shap.predicted_class || shap.prediction);

  // Class probabilities for XGBoost (Requirement 12: mostly grayscale distribution + highlight predicted class)
  const probData = useMemo(() => {
    if (!isMlRiskAvailable || !risk?.class_probabilities) return [];
    const canonicalOrder = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    return canonicalOrder
      .filter((className) => className in risk.class_probabilities)
      .map((className) => {
        const isPredicted = className === risk.predicted_class;
        return {
          name: className,
          probability: typeof risk.class_probabilities[className] === 'number'
            ? Number((risk.class_probabilities[className] * 100).toFixed(1))
            : 0,
          color: isPredicted ? '#111111' : '#D4D4D0',
          isPredicted,
        };
      });
  }, [risk, isMlRiskAvailable]);

  // SHAP waterfall data
  const shapData = useMemo(() => {
    if (!isShapAvailable || !shap?.feature_contributions) return [];
    return [...shap.feature_contributions]
      .sort((a, b) => (b.absolute_shap_value || 0) - (a.absolute_shap_value || 0))
      .map((c) => ({
        name: c.feature_name.replace(/_/g, ' '),
        rawKey: c.feature_name,
        shap_value: Number((c.shap_value || 0).toFixed(4)),
        abs_value: Number((c.absolute_shap_value || 0).toFixed(4)),
        direction: c.direction,
        original_value: c.original_value,
        model_input_value: c.model_input_value,
      }));
  }, [shap, isShapAvailable]);

  // 19D Feature Representation Grouped into 7 Canonical Domains (Requirement 13)
  const categorized19DFeatures = useMemo(() => {
    const categoryMapping = {
      'TLS': [
        'tls_version_numeric',
        'cipher_security_score',
        'key_exchange_strength',
        'pfs_enabled',
      ],
      'Certificate/PKI': [
        'certificate_key_size',
        'certificate_signature_strength',
        'certificate_validity_status',
        'san_present',
        'hostname_match_status',
        'trust_validation_status',
        'revocation_status',
      ],
      'STARTTLS': [
        'starttls_downgrade',
      ],
      'Findings': [
        'compliance_violation_count',
        'unknown_finding_count',
        'high_critical_finding_count',
      ],
      'Threat Intelligence': [
        'vulnerability_count',
        'threat_mapping_count',
      ],
      'Cryptography': [
        'cryptographic_security_score',
      ],
      'JA4': [
        'ja4_available',
      ],
    };

    return Object.entries(categoryMapping).map(([catName, keys]) => {
      const feats = keys.map((key) => {
        const found = canonicalFeatures.find((f) => f.key === key);
        if (found) return { ...found, category: catName };
        return {
          key,
          name: key.replace(/_/g, ' '),
          category: catName,
          value: null,
          interpretation: 'Not available from capture',
        };
      });
      return {
        category: catName,
        features: feats,
      };
    });
  }, [canonicalFeatures]);

  // Threat categories
  const threatCategories = useMemo(() => {
    const cats = new Set(threats.map((t) => t.category).filter(Boolean));
    return Array.from(cats);
  }, [threats]);

  // Filtered threats
  const filteredThreats = useMemo(() => {
    return threats.filter((t) => {
      const matchCat = threatCategory === 'ALL' || t.category === threatCategory;
      const term = threatSearch.toLowerCase();
      const matchSearch =
        !term ||
        t.title?.toLowerCase().includes(term) ||
        t.description?.toLowerCase().includes(term) ||
        t.mitre_attack?.technique_id?.toLowerCase().includes(term) ||
        t.mitre_attack?.technique_name?.toLowerCase().includes(term) ||
        t.upstream_finding_id?.toLowerCase().includes(term);

      return matchCat && matchSearch;
    });
  }, [threats, threatCategory, threatSearch]);

  // Filtered vulnerabilities
  const filteredVulns = useMemo(() => {
    return vulnerabilities.filter((v) => {
      const term = vulnSearch.toLowerCase();
      return (
        !term ||
        v.title?.toLowerCase().includes(term) ||
        v.description?.toLowerCase().includes(term) ||
        v.identifier?.toLowerCase().includes(term) ||
        v.vulnerability_id?.toLowerCase().includes(term) ||
        v.source_finding_id?.toLowerCase().includes(term)
      );
    });
  }, [vulnerabilities, vulnSearch]);

  if (!analysisId || !report) {
    return (
      <EmptyAnalysisState
        title="START ANALYSIS"
        description="Run an analysis to generate statistical and explainable risk intelligence."
        buttonText="Start Analysis"
        supportingText="Mail Rakhwala will reconstruct email streams, audit TLS/PKI, evaluate security rules, and generate evidence-linked intelligence."
        featureBadge="Statistical Risk Intelligence"
      />
    );
  }

  const deterministicSeverity = isApplicable ? (posture?.severity || 'UNKNOWN') : 'NOT_APPLICABLE';
  const mlPredictedClass = isMlRiskAvailable ? risk.predicted_class : null;

  return (
    <div className="p-6 sm:p-8 max-w-7xl mx-auto space-y-6 bg-[#F7F7F5]">
      <PageHeader
        category="INTELLIGENCE"
        title="Risk Intelligence"
        description="Unified risk intelligence contrasting deterministic RFC cryptographic posture against statistical ML classifiers, Isolation Forest outlier telemetry, 19D feature inspection, SHAP explainability, and MITRE ATT&CK correlation."
        onRefresh={reload}
        isRefreshing={loading}
      />

      {loading && !report ? (
        <LoadingState
          title="Risk Intelligence Synthesis"
          message="Contrasting deterministic scoring against statistical ML, 19D vectors, and SHAP explainability..."
        />
      ) : error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-6 text-red-700">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-6 w-6 text-red-600" />
            <span className="font-semibold">Failed to load risk intelligence</span>
          </div>
          <p className="mt-2 text-sm text-red-600">{error}</p>
        </div>
      ) : (
        <>
          {/* Non-Email Informational Notice if applicable */}
          {!isApplicable && (
            <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-xs text-amber-900 flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold text-sm block mb-0.5">
                  Assessment Not Applicable: Non-Email Capture
                </span>
                {applicabilityReason} Email security posture, deterministic RFC rules, and ML risk classification were not evaluated.
              </div>
            </div>
          )}

          {/* Sub-Navigation Tabs */}
          <div className="flex items-center gap-1.5 border-b border-[#E5E5E0] pb-2 overflow-x-auto text-xs">
            {SECTIONS.map((sec) => {
              const Icon = sec.icon;
              const isActive = activeTab === sec.id;
              return (
                <button
                  key={sec.id}
                  onClick={() => setActiveTab(sec.id)}
                  className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg font-bold transition-all shrink-0 ${
                    isActive
                      ? 'bg-[#111111] text-white shadow-sm'
                      : 'text-[#666666] bg-white border border-[#E5E5E0] hover:bg-[#F7F7F5] hover:text-[#111111]'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  <span>{sec.label}</span>
                </button>
              );
            })}
          </div>

          {/* TAB 1: DUAL-ENGINE OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Dual-Engine Comparative Banners */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Engine A: Deterministic Cryptographic Posture */}
                <div className="rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm flex flex-col justify-between">
                  <div className="space-y-4">
                    {/* Header */}
                    <div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <ShieldCheck className="h-5 w-5 text-[#111111]" />
                          <span className="text-xs uppercase font-extrabold tracking-wider text-[#111111]">
                            AUTHORITATIVE SECURITY ENGINE
                          </span>
                        </div>
                        <span className="text-[10px] font-mono bg-neutral-100 text-neutral-800 border border-neutral-200 px-2 py-0.5 rounded font-semibold">
                          100% REPRODUCIBLE (RFC COMPLIANCE)
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs text-[#666666] font-medium">
                        Evaluate observed email traffic against explicit deterministic security rules.
                      </p>
                    </div>

                    {/* Output Verdict Block */}
                    <div className="rounded-xl border border-slate-200 bg-white p-3.5 shadow-2xs">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-500">
                          AUTHORITATIVE VERDICT
                        </span>
                        <span className="text-[10px] font-semibold text-neutral-600">19 Canonical Rules</span>
                      </div>
                      <div className="flex flex-wrap items-baseline justify-between gap-2">
                        <div className="flex items-baseline gap-2.5">
                          <span
                            className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-extrabold ${
                              isApplicable
                                ? getSeverityBadge(deterministicSeverity).badge
                                : 'bg-slate-100 text-slate-700 border border-slate-200'
                            }`}
                          >
                            {deterministicSeverity} RISK
                          </span>
                          <span className="text-xs text-slate-600">
                            Posture Score:{' '}
                            <strong className="text-slate-900 text-sm">
                              {isApplicable && postureScore !== null ? `${postureScore}/100` : 'Not Applicable'}
                            </strong>
                          </span>
                        </div>
                        {isApplicable && postureScore !== null && (
                          <span className="text-xs font-mono font-semibold text-rose-600">
                            Total Deductions: −{analytics.totalPenalty} pts
                          </span>
                        )}
                      </div>

                      <div className="mt-3 grid grid-cols-2 gap-2 text-xs font-mono bg-neutral-50 rounded-lg border border-neutral-200 p-2.5">
                        <div>
                          <span className="text-[9px] text-neutral-500 uppercase tracking-wider block font-bold">Unique Violated Rules</span>
                          <span className="font-black text-[#111111] text-sm">{analytics.uniqueViolatedRulesCount}</span>
                        </div>
                        <div>
                          <span className="text-[9px] text-neutral-500 uppercase tracking-wider block font-bold">Finding Instances</span>
                          <span className="font-black text-[#111111] text-sm">{analytics.totalFindings}</span>
                        </div>
                      </div>
                    </div>

                    {/* Top 3 Verified Findings */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-500">
                          TOP VERIFIED FINDINGS ({analytics.uniqueViolatedRules.length})
                        </span>
                        <button
                          onClick={() => setActiveTab('threats')}
                          className="text-[10px] font-semibold text-neutral-700 hover:text-[#111111] flex items-center gap-0.5"
                        >
                          <span>Evidence Explorer</span>
                          <ArrowRight className="h-3 w-3" />
                        </button>
                      </div>

                      {analytics.uniqueViolatedRules.length > 0 ? (
                        <div className="space-y-2">
                          {analytics.uniqueViolatedRules.slice(0, 3).map((rule) => {
                            return (
                              <div
                                key={rule.ruleId}
                                className="rounded-xl border border-rose-200 bg-rose-50/60 p-2.5 text-xs text-rose-900 space-y-1"
                              >
                                <div className="font-bold flex items-center justify-between">
                                  <span className="flex items-center gap-1.5 text-rose-950 font-extrabold truncate max-w-[280px]">
                                    <AlertTriangle className="h-3.5 w-3.5 text-rose-600 shrink-0" />
                                    {rule.ruleId}: {rule.title}
                                  </span>
                                  <span
                                    className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold ${
                                      getSeverityBadge(rule.severity).badge
                                    }`}
                                  >
                                    {rule.severity}
                                  </span>
                                </div>
                                <div className="flex items-center justify-between text-[10px] text-slate-600 pt-0.5">
                                  <span className="font-mono">
                                    {rule.instances.length} {rule.instances.length === 1 ? 'evidence instance' : 'evidence instances'}
                                  </span>
                                  {rule.penaltyApplied > 0 && (
                                    <span className="font-bold text-rose-700 shrink-0">−{rule.penaltyApplied} pts applied</span>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      ) : (
                        <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-3 text-xs text-slate-600">
                          {isApplicable
                            ? 'No non-compliant findings detected in this capture.'
                            : 'No email security findings evaluated.'}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="mt-6 pt-4 border-t border-[#E5E5E0] flex items-center justify-between text-xs text-slate-500">
                    <span><strong className="text-slate-800">{analytics.totalFindings}</strong> Finding Instances</span>
                    <span>Engine: <strong className="text-slate-800">RFC Conformance (19 Canonical Rules)</strong></span>
                  </div>
                </div>

                {/* Engine B: Supervised XGBoost ML Risk Classification */}
                <div className="rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm flex flex-col justify-between">
                  <div className="space-y-4">
                    {/* Header */}
                    <div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Brain className="h-5 w-5 text-[#111111]" />
                          <span className="text-xs uppercase font-extrabold tracking-wider text-[#111111]">
                            STATISTICAL ML INTELLIGENCE
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-[10px] font-mono bg-neutral-100 text-neutral-800 border border-neutral-200 px-2 py-0.5 rounded font-semibold">
                            XGBOOST
                          </span>
                          <span className="text-[10px] font-mono bg-neutral-100 text-neutral-800 border border-neutral-200 px-2 py-0.5 rounded font-semibold">
                            Statistical Risk Model
                          </span>
                        </div>
                      </div>
                      <p className="mt-1.5 text-xs text-[#666666] font-medium">
                        Analyze the canonical 19-dimensional security representation for statistical risk patterns.
                      </p>
                    </div>

                    {/* Output Verdict Block */}
                    <div className="rounded-xl border border-slate-200 bg-white p-3.5 shadow-2xs">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-500">
                          STATISTICAL PREDICTION
                        </span>
                        <span className="text-[10px] font-semibold text-neutral-600">19D Feature Space</span>
                      </div>

                      {!isApplicable ? (
                        <div className="inline-flex items-center gap-2 text-xs text-slate-500">
                          <Info className="h-4 w-4 text-slate-400" />
                          <span>ML inference not applicable: Non-email capture</span>
                        </div>
                      ) : mlPredictedClass ? (
                        <div className="flex flex-wrap items-baseline justify-between gap-2">
                          <div className="flex items-baseline gap-2.5">
                            <span
                              className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-extrabold ${
                                getSeverityBadge(mlPredictedClass).badge
                              }`}
                            >
                              {mlPredictedClass} PREDICTED
                            </span>
                            <span className="text-xs text-slate-600">
                              Class ID: <strong className="text-slate-900 font-mono">{risk.class_id}</strong>
                            </span>
                          </div>
                          {(typeof risk.confidence === 'number' || typeof risk.probabilities?.[mlPredictedClass] === 'number') && (
                            <span className="text-xs text-slate-600">
                              Probability:{' '}
                              <strong className="text-[#111111] font-mono font-bold">
                                {((typeof risk.confidence === 'number' ? risk.confidence : risk.probabilities[mlPredictedClass]) * 100).toFixed(1)}%
                              </strong>
                            </span>
                          )}
                        </div>
                      ) : (
                        <div className="inline-flex items-center gap-2 text-xs text-slate-500">
                          <Info className="h-4 w-4 text-slate-400" />
                          <span>ML inference unavailable: {risk?.reason?.replace(/_/g, ' ') || 'trained model artifact not loaded'}</span>
                        </div>
                      )}
                    </div>

                    {/* Four-Class Probability Distribution Pills */}
                    {probData.length > 0 && (
                      <div className="rounded-xl border border-slate-200 bg-white p-3 shadow-2xs space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-500">
                            CLASS PROBABILITIES
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono">Softmax</span>
                        </div>
                        <div className="grid grid-cols-4 gap-1.5">
                          {probData.map((p) => (
                            <div
                              key={p.name}
                              className={`rounded-lg p-1.5 text-center border ${
                                p.name === mlPredictedClass
                                  ? 'border-[#111111] bg-neutral-100 font-bold'
                                  : 'border-slate-100 bg-slate-50/60'
                              }`}
                            >
                              <div className="text-[10px] font-semibold text-slate-500">{p.name}</div>
                              <div className="text-xs font-mono font-extrabold text-slate-800">{p.probability}%</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Top 3 SHAP Signals */}
                    <div className="rounded-xl border border-neutral-200 bg-neutral-50/60 p-3 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-extrabold uppercase tracking-wider text-[#111111]">
                          TOP 3 SHAP SIGNALS
                        </span>
                        <button
                          onClick={() => setActiveTab('shap')}
                          className="text-[10px] font-semibold text-neutral-700 hover:text-[#111111] flex items-center gap-0.5"
                        >
                          <span>Explore SHAP</span>
                          <ArrowRight className="h-3 w-3" />
                        </button>
                      </div>

                      {shapData && shapData.length > 0 ? (
                        <div className="space-y-1.5">
                          {shapData.slice(0, 3).map((s, idx) => (
                            <div key={idx} className="flex items-center justify-between text-xs bg-white rounded-lg px-2.5 py-1.5 border border-neutral-200">
                              <span className="font-mono text-[11px] text-slate-800 truncate max-w-[220px]">
                                {s.rawKey}
                              </span>
                              <span
                                className={`font-mono text-[11px] font-bold ${
                                  s.direction === 'INCREASES_PREDICTED_CLASS' || s.direction === 'increases_risk'
                                    ? 'text-rose-600'
                                    : 'text-emerald-600'
                                }`}
                              >
                                {s.shap_value > 0 ? '+' : ''}{s.shap_value.toFixed(4)}
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-slate-500 italic">SHAP attribution unavailable for this capture.</p>
                      )}
                    </div>
                  </div>

                  <div className="mt-6 pt-4 border-t border-[#E5E5E0] flex items-center justify-between text-xs text-slate-500">
                    <span className="italic">Secondary statistical signal — does not modify authoritative posture.</span>
                  </div>
                </div>
              </div>

              {/* Statistical Probability Distribution Chart */}
              {probData.length > 0 ? (
                <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <h3 className="text-base font-bold text-slate-900">
                        Estimated Class Probabilities
                      </h3>
                      <p className="text-xs text-slate-500 mt-0.5">
                        Continuous softmax probability distribution across the 4 risk categories
                      </p>
                    </div>
                    <span className="text-xs font-mono bg-slate-100 text-slate-700 px-2 py-1 rounded font-bold">
                      Sum: 100%
                    </span>
                  </div>

                  <div className="h-64 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={probData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                        <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} />
                        <YAxis
                          stroke="#94a3b8"
                          fontSize={11}
                          unit="%"
                          domain={[0, 100]}
                          tickLine={false}
                        />
                        <Tooltip
                          content={({ active, payload }) => {
                            if (active && payload && payload.length) {
                              const data = payload[0].payload;
                              return (
                                <div className="rounded-lg border border-[#222222] bg-[#111111] p-2.5 shadow-lg text-xs text-white">
                                  <p className="font-semibold text-white">{data.name} Risk</p>
                                  <p className="text-neutral-400 font-mono mt-1">
                                    Probability: <strong className="text-white">{data.probability}%</strong>
                                  </p>
                                </div>
                              );
                            }
                            return null;
                          }}
                        />
                        <Bar dataKey="probability" radius={[6, 6, 0, 0]}>
                          {probData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Numerical breakdown bar cards */}
                  <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3">
                    {probData.map((p) => (
                      <div key={p.name} className="rounded-xl border border-slate-100 bg-slate-50/60 p-3">
                        <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-500">
                          {p.name}
                        </span>
                        <div className="text-xl font-black text-slate-900 font-mono mt-1">
                          {p.probability}%
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm text-center">
                  <h3 className="text-base font-bold text-slate-900 mb-1">
                    Estimated Class Probabilities
                  </h3>
                  <p className="text-sm text-slate-500">
                    Probability distribution unavailable
                  </p>
                </div>
              )}

              {/* Model Hyperparameters & Architecture */}
              {risk?.model_metadata && (
                <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                  <h3 className="text-base font-bold text-slate-900 mb-4">
                    Model Hyperparameters & Training Configuration
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                    <div className="rounded-xl border border-slate-100 bg-slate-50 p-3">
                      <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                        Estimators
                      </span>
                      <div className="text-base font-bold text-slate-800 font-mono mt-0.5">
                        {risk.model_metadata.n_estimators ?? 100} trees
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-100 bg-slate-50 p-3">
                      <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                        Max Depth
                      </span>
                      <div className="text-base font-bold text-slate-800 font-mono mt-0.5">
                        {risk.model_metadata.max_depth ?? 4}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-100 bg-slate-50 p-3">
                      <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                        Learning Rate (η)
                      </span>
                      <div className="text-base font-bold text-slate-800 font-mono mt-0.5">
                        {risk.model_metadata.learning_rate ?? 0.1}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-100 bg-slate-50 p-3">
                      <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                        Random Seed
                      </span>
                      <div className="text-base font-bold text-slate-800 font-mono mt-0.5">
                        {risk.model_metadata.random_state ?? 42}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-100 bg-slate-50 p-3">
                      <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                        Features
                      </span>
                      <div className="text-base font-bold text-slate-800 font-mono mt-0.5">
                        {risk.model_metadata.feature_count ?? 19} dims
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Methodological Notice */}
              <div className="rounded-xl border border-amber-200 bg-amber-50/50 p-4 text-xs text-amber-900 leading-relaxed space-y-1.5">
                <div className="font-bold flex items-center gap-1.5">
                  <Scale className="h-4 w-4 text-amber-700" />
                  Methodological Distinction & Demonstration Disclaimer
                </div>
                <p>
                  <strong>DETERMINISTIC SECURITY ENGINE</strong> outputs are calculated directly from RFC conformance and cryptographic specifications.
                  They are 100% reproducible without statistical variance and serve as the authoritative security evaluation.
                </p>
                <p>
                  <strong>STATISTICAL ML INTELLIGENCE (Statistical Risk Model):</strong> This machine learning model provides secondary statistical risk intelligence based on Mail Rakhwala baseline telemetry and behavioral patterns. Machine learning outputs reflect statistical pattern distributions and do not denote a confirmed cyber attack, active exploitation, or system breach.
                </p>
              </div>
            </div>
          )}

          {/* TAB 2: ANOMALY DETECTION */}
          {activeTab === 'anomaly' && (
            <div className="space-y-6">
              {isAnomalyAvailable ? (
                <div
                  className={`rounded-2xl border p-6 transition-all ${
                    anomaly.is_anomalous
                      ? 'border-amber-200 bg-gradient-to-r from-amber-50/80 via-white to-amber-50/40 shadow-sm'
                      : 'border-emerald-200 bg-gradient-to-r from-emerald-50/80 via-white to-emerald-50/40 shadow-sm'
                  }`}
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="flex items-start gap-4">
                      <div
                        className={`mt-1 flex h-12 w-12 shrink-0 items-center justify-center rounded-xl ${
                          anomaly.is_anomalous
                            ? 'bg-amber-100 text-amber-700'
                            : 'bg-emerald-100 text-emerald-700'
                        }`}
                      >
                        {anomaly.is_anomalous ? (
                          <AlertTriangle className="h-6 w-6" />
                        ) : (
                          <CheckCircle2 className="h-6 w-6" />
                        )}
                      </div>
                      <div>
                        <div className="flex items-center gap-3 flex-wrap">
                          <h2 className="text-xl font-bold text-slate-900">
                            {anomaly.is_anomalous
                              ? 'Statistical Outlier Detected'
                              : 'Normal Protocol Pattern'}
                          </h2>
                          <span
                            className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                              anomaly.is_anomalous
                                ? 'bg-amber-100 text-amber-800'
                                : 'bg-emerald-100 text-emerald-800'
                            }`}
                          >
                            Prediction: {anomaly.prediction === 1 ? '+1 (Normal)' : '-1 (Outlier)'}
                          </span>
                          <span className="inline-flex items-center rounded-full bg-purple-100 text-purple-800 px-2.5 py-0.5 text-xs font-semibold">
                            Statistical Risk Model
                          </span>
                        </div>
                        <p className="mt-1 text-sm text-slate-600 leading-relaxed max-w-3xl">
                          {safeVal(anomaly.status_text, 'Statistical evaluation completed.')}
                        </p>
                      </div>
                    </div>

                    <div className="flex flex-col items-end shrink-0 border-t md:border-t-0 md:border-l border-slate-200 pt-3 md:pt-0 md:pl-6">
                      <span className="text-xs uppercase tracking-wider font-semibold text-slate-500">
                        Decision Function Score
                      </span>
                      <span className="text-3xl font-extrabold tracking-tight text-slate-900 font-mono mt-0.5">
                        {typeof anomaly.anomaly_score === 'number'
                          ? anomaly.anomaly_score.toFixed(4)
                          : 'N/A'}
                      </span>
                      <span className="text-[11px] text-slate-400 mt-0.5">
                        Lower values indicate higher abnormality
                      </span>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="rounded-2xl border border-[#E5E5E0] bg-[#F7F7F5] p-6 shadow-sm">
                  <div className="flex items-start gap-4">
                    <div className="mt-1 flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-[#111111] text-white">
                      <Info className="h-6 w-6" />
                    </div>
                    <div>
                      <h3 className="text-base font-bold text-slate-900">
                        ML inference unavailable: {anomaly?.reason || 'trained_model_artifact_unavailable'}
                      </h3>
                      <p className="mt-1 text-sm text-slate-600 leading-relaxed max-w-3xl">
                        The unsupervised Isolation Forest anomaly model is unavailable ({anomaly?.reason ? anomaly.reason.replace(/_/g, ' ') : 'no trained model artifact loaded'}).
                        Deterministic RFC compliance findings and cryptographic posture scoring remain 100% active and authoritative.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Model Configuration / Metadata Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                  <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold uppercase tracking-wider">
                    <Cpu className="h-4 w-4 text-[#111111]" /> Model Algorithm
                  </div>
                  <div className="mt-2 text-lg font-bold text-slate-900">
                    {anomaly?.model_metadata?.model_name || 'IsolationForest'}
                  </div>
                  <div className="text-xs text-slate-400 mt-1">Unsupervised tree outlier estimator</div>
                </div>

                <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                  <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold uppercase tracking-wider">
                    <Layers className="h-4 w-4 text-indigo-600" /> Isolation Trees
                  </div>
                  <div className="mt-2 text-lg font-bold text-slate-900 font-mono">
                    {anomaly?.model_metadata?.n_estimators ?? 100}
                  </div>
                  <div className="text-xs text-slate-400 mt-1">Ensemble estimators partitioned</div>
                </div>

                <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                  <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold uppercase tracking-wider">
                    <Activity className="h-4 w-4 text-emerald-600" /> Contamination
                  </div>
                  <div className="mt-2 text-lg font-bold text-slate-900 font-mono">
                    {safeVal(anomaly?.model_metadata?.contamination, 'auto')}
                  </div>
                  <div className="text-xs text-slate-400 mt-1">Expected proportion of outliers</div>
                </div>

                <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                  <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold uppercase tracking-wider">
                    <Hash className="h-4 w-4 text-purple-600" /> Feature Dimensions
                  </div>
                  <div className="mt-2 text-lg font-bold text-slate-900 font-mono">
                    {anomaly?.feature_count ?? 19}
                  </div>
                  <div className="text-xs text-slate-400 mt-1">Canonical deterministic vector dimensions</div>
                </div>
              </div>

              {/* Scientific Disclaimer */}
              <div className="rounded-xl border border-amber-200 bg-amber-50/60 p-4 text-xs text-amber-900 leading-relaxed space-y-1">
                <div className="font-semibold text-slate-800 flex items-center gap-1.5">
                  <Info className="h-4 w-4 text-amber-700" />
                  Methodology & Demonstration Limitations
                </div>
                <p>
                  <strong>Statistical Risk Model:</strong> This machine learning model provides secondary statistical risk intelligence based on Mail Rakhwala baseline telemetry and behavioral patterns.
                </p>
                <p>
                  An anomaly identified by Isolation Forest represents a statistical outlier relative to reference baseline distributions. It does not constitute causal proof of an attack, intrusion, or system compromise. Deterministic RFC compliance findings and cryptographic posture audits remain the authoritative baseline.
                </p>
              </div>
            </div>
          )}

          {/* TAB 3: 19D FEATURE VECTOR */}
          {activeTab === 'feature-vector' && (
            <div className="space-y-6">
              {canonicalFeatures.length > 0 ? (
                <>
                  {/* Alert Callout if any backend vector mismatch was identified */}
                  {vectorMismatches.length > 0 && (
                    <div className="rounded-2xl border border-amber-300 bg-gradient-to-r from-amber-50/90 via-white to-amber-50/40 p-5 shadow-sm space-y-2">
                      <div className="flex items-center gap-2 text-amber-900 font-bold text-sm">
                        <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0" />
                        <span>Intelligence Cross-Validation: Backend Vector Mismatch Detected</span>
                      </div>
                      {vectorMismatches.map((m) => (
                        <p key={m.key} className="text-xs text-amber-800 leading-relaxed">
                          {m.mismatch.message}
                        </p>
                      ))}
                      <p className="text-[11px] text-amber-700/90 leading-relaxed pt-1 border-t border-amber-200/60">
                        <strong>Truthful Representation Notice:</strong> MailRakhwala faithfully preserves the raw backend vector value
                        (<code>0.0</code>) without silent client-side overwriting, while prominently surfacing the authoritative RFC finding
                        to prevent false or misleading claims of "Clean / Normal negotiation".
                      </p>
                    </div>
                  )}

                  {/* Grouped Feature Domains Overview */}
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-base font-bold text-slate-900">
                        Deterministic Feature Vector Domains
                      </h3>
                      <p className="text-xs text-slate-500 mt-0.5">
                        19-dimensional mathematical representation evaluated across 5 functional categories
                      </p>
                    </div>
                    <span className="text-xs font-mono bg-white text-[#111111] border border-[#E5E5E0] px-2.5 py-1 rounded-lg font-bold shadow-xs">
                      19 Canonical Dimensions Verified
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {categorized19DFeatures.map((cat) => (
                      <div key={cat.category} className="rounded-2xl border border-[#E5E5E0] bg-white p-5 shadow-sm space-y-3">
                        <div className="flex items-center justify-between border-b border-[#E5E5E0] pb-2.5">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-black uppercase tracking-wider text-[#111111]">
                              {cat.category}
                            </span>
                            <span className="text-[10px] font-mono text-neutral-400 font-bold px-1.5 py-0.2 rounded bg-[#F7F7F5] border border-[#E5E5E0]">
                              {cat.features.length} {cat.features.length === 1 ? 'dim' : 'dims'}
                            </span>
                          </div>
                        </div>

                        <div className="space-y-2.5">
                          {cat.features.map((f) => {
                            const isNull = f.value === null || f.value === undefined;
                            const isZero = f.value === 0 || f.value === 0.0;
                            const isNA = f.value === -1 || f.value === -1.0;

                            return (
                              <div key={f.key} className="p-2.5 rounded-xl border border-[#F0F0EB] bg-[#FAFAF8] space-y-1.5 transition hover:border-[#D0D0CA]">
                                <div className="flex items-center justify-between gap-2">
                                  <span className="text-xs font-bold text-[#111111] truncate" title={f.name}>
                                    {f.name}
                                  </span>
                                  <div className="flex items-center gap-1.5 shrink-0">
                                    {f.mismatch && (
                                      <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-amber-100 text-amber-900 border border-amber-300" title={f.mismatch.message}>
                                        Mismatch
                                      </span>
                                    )}
                                    {isNull ? (
                                      <span className="px-2 py-0.5 rounded text-[10px] font-mono text-neutral-500 bg-[#EAEAE8] border border-[#D5D5D0]">
                                        null
                                      </span>
                                    ) : isNA ? (
                                      <span className="px-2 py-0.5 rounded text-[10px] font-mono text-neutral-500 bg-[#EAEAE8] border border-[#D5D5D0]">
                                        −1.0 (N/A)
                                      </span>
                                    ) : isZero ? (
                                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                        f.mismatch ? 'bg-amber-100 text-amber-900 border border-amber-300' : 'bg-[#EAEAE8] text-[#111111] border border-[#D5D5D0]'
                                      }`}>
                                        0.0
                                      </span>
                                    ) : (
                                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#111111] text-white shadow-xs">
                                        {f.value}
                                      </span>
                                    )}
                                  </div>
                                </div>

                                {/* Normalized Analytical Feature Bar */}
                                <div className="h-1.5 w-full bg-[#E5E5E0] rounded-full overflow-hidden">
                                  <div
                                    className={`h-full rounded-full transition-all duration-300 ${
                                      isNull || isNA ? 'w-0' : isZero ? 'w-1 bg-neutral-400' : 'bg-[#111111]'
                                    }`}
                                    style={{
                                      width: isNull || isNA ? '0%' : isZero ? '4%' : `${Math.min(100, Math.max(10, f.value > 10 ? f.value : f.value * 25))}%`,
                                    }}
                                  />
                                </div>

                                <p className="text-[10px] text-[#666666] leading-relaxed truncate" title={f.interpretation}>
                                  {f.interpretation}
                                </p>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Canonical 19-Dimensional Feature Vector Table */}
                  <div className="rounded-2xl border border-slate-200 bg-white overflow-hidden shadow-sm">
                    <div className="border-b border-slate-100 bg-slate-50/75 px-6 py-4 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <FileSearch className="h-4 w-4 text-slate-600" />
                        <h3 className="text-sm font-bold text-slate-800">
                          Exact 19-Dimensional Feature Vector Inspection
                        </h3>
                      </div>
                      <span className="text-xs text-slate-500 font-mono">
                        Explicit Canonical Mapping (RFC 8314 & PKI Baselines)
                      </span>
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead className="border-b border-slate-200 bg-slate-50 font-semibold text-slate-600">
                          <tr>
                            <th className="py-2.5 px-6">#</th>
                            <th className="py-2.5 px-4">Feature Name</th>
                            <th className="py-2.5 px-4 font-mono">Canonical Backend Key</th>
                            <th className="py-2.5 px-4">Domain</th>
                            <th className="py-2.5 px-4 text-right">Raw Value</th>
                            <th className="py-2.5 px-6">Authoritative Interpretation</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {canonicalFeatures.map((item) => (
                            <tr
                              key={item.key}
                              className={`transition-colors ${
                                item.mismatch ? 'bg-amber-50/40 hover:bg-amber-50/70' : 'hover:bg-slate-50/60'
                              }`}
                            >
                              <td className="py-2.5 px-6 font-mono text-slate-400">{item.index}</td>
                              <td className="py-2.5 px-4 font-medium text-slate-900">
                                <div className="flex items-center gap-2">
                                  <span>{item.name}</span>
                                  {item.mismatch && (
                                    <span className="inline-flex items-center gap-1 rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-bold text-amber-900">
                                      <AlertTriangle className="h-3 w-3 text-amber-700" />
                                      Mismatch
                                    </span>
                                  )}
                                </div>
                              </td>
                              <td className="py-2.5 px-4 font-mono text-slate-500">{item.key}</td>
                              <td className="py-2.5 px-4 text-slate-500">{item.domain}</td>
                              <td className="py-2.5 px-4 text-right font-mono font-bold text-slate-900">
                                {item.value !== null ? item.value : 'null'}
                              </td>
                              <td className="py-2.5 px-6 text-slate-700">
                                <div className="space-y-1">
                                  <div>{item.interpretation}</div>
                                  {item.mismatch && (
                                    <div className="text-[11px] text-amber-800 font-medium">
                                      Authoritative Source: {item.mismatch.authoritativeSource} ({item.mismatch.authoritativeSeverity} Severity)
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </>
              ) : (
                <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-slate-500 text-sm">
                  Not evaluated for this analysis.
                </div>
              )}
            </div>
          )}

          {/* TAB 4: ML EXPLAINABILITY (SHAP) */}
          {activeTab === 'shap' && (
            <div className="space-y-6">
              {isShapAvailable ? (
                <>
                  <div className="rounded-2xl border border-[#E5E5E0] bg-white p-6 shadow-sm">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                      <div className="flex items-start gap-4">
                        <div className="mt-1 flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-[#111111] text-white">
                          <Brain className="h-6 w-6" />
                        </div>
                        <div>
                          <div className="flex items-center gap-3 flex-wrap">
                            <h2 className="text-xl font-bold text-[#111111]">
                              Local Feature Attribution Ready
                            </h2>
                            <span className="inline-flex items-center rounded-full bg-neutral-100 text-[#111111] border border-neutral-200 px-2.5 py-0.5 text-xs font-semibold">
                              Target Class: {shap.predicted_class}
                            </span>
                            <span className="inline-flex items-center rounded-full bg-neutral-100 text-neutral-700 border border-neutral-200 px-2.5 py-0.5 text-xs font-semibold">
                              Statistical Risk Model
                            </span>
                          </div>
                          <p className="mt-1 text-xs text-slate-600 leading-relaxed max-w-3xl">
                            {safeVal(shap.status_text, 'SHAP local explanations quantify the contribution of each network feature.')}
                          </p>
                        </div>
                      </div>

                      <div className="flex flex-col items-end shrink-0 border-t md:border-t-0 md:border-l border-slate-200 pt-3 md:pt-0 md:pl-6">
                        <span className="text-xs uppercase font-semibold text-slate-500">
                          Explainer Engine
                        </span>
                        <span className="text-lg font-bold text-slate-900 font-mono mt-0.5">
                          {shap.model_metadata?.explainer_name || 'TreeExplainer'}
                        </span>
                        <span className="text-[11px] text-slate-400">
                          Base Value (Margin): {typeof shap.model_metadata?.base_value === 'number' ? shap.model_metadata.base_value.toFixed(3) : '0.000'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* SHAP Feature Attribution Waterfall Chart */}
                  {shapData.length > 0 && (
                    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                      <div className="flex items-center justify-between mb-4">
                        <div>
                          <h3 className="text-base font-bold text-slate-900">
                            SHAP Feature Contribution Rankings
                          </h3>
                          <p className="text-xs text-slate-500 mt-0.5">
                            Positive SHAP values push towards predicted risk; negative values mitigate risk
                          </p>
                        </div>
                        <div className="flex items-center gap-4 text-xs">
                          <span className="flex items-center gap-1.5 text-rose-600 font-medium">
                            <span className="h-2.5 w-2.5 rounded-full bg-rose-500" /> Increases Risk
                          </span>
                          <span className="flex items-center gap-1.5 text-emerald-600 font-medium">
                            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" /> Decreases Risk
                          </span>
                        </div>
                      </div>

                      <div className="h-96 w-full">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart
                            data={shapData}
                            layout="vertical"
                            margin={{ top: 5, right: 30, left: 160, bottom: 5 }}
                          >
                            <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f1f5f9" />
                            <XAxis type="number" stroke="#94a3b8" fontSize={11} tickLine={false} />
                            <YAxis
                              dataKey="name"
                              type="category"
                              stroke="#64748b"
                              fontSize={11}
                              tickLine={false}
                              width={160}
                            />
                            <Tooltip
                              content={({ active, payload }) => {
                                if (active && payload && payload.length) {
                                  const item = payload[0].payload;
                                  return (
                                    <div className="rounded-lg border border-slate-200 bg-white p-3 shadow-lg text-xs space-y-1">
                                      <p className="font-semibold text-slate-800">{item.name}</p>
                                      <p className="text-slate-500 font-mono">
                                        SHAP Value: <strong className={item.shap_value >= 0 ? 'text-rose-600' : 'text-emerald-600'}>{item.shap_value}</strong>
                                      </p>
                                      <p className="text-slate-400 font-mono text-[11px]">
                                        Model Input: {item.model_input_value} (Raw: {item.original_value})
                                      </p>
                                    </div>
                                  );
                                }
                                return null;
                              }}
                            />
                            <ReferenceLine x={0} stroke="#94a3b8" />
                            <Bar dataKey="shap_value" radius={[0, 4, 4, 0]}>
                              {shapData.map((entry, index) => (
                                <Cell
                                  key={`cell-${index}`}
                                  fill={entry.shap_value >= 0 ? '#f43f5e' : '#10b981'}
                                />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                  )}

                  {/* Detailed Feature Contributions Table */}
                  {shapData.length > 0 && (
                    <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden">
                      <div className="border-b border-slate-100 bg-slate-50/75 px-6 py-4 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <FileSearch className="h-4 w-4 text-slate-600" />
                          <h3 className="text-sm font-bold text-slate-800">
                            Complete Feature Attribution Table
                          </h3>
                        </div>
                        <span className="text-xs font-mono text-slate-500">
                          {shapData.length} Dimensions Analyzed
                        </span>
                      </div>

                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs">
                          <thead className="border-b border-slate-200 bg-slate-50 font-semibold text-slate-600">
                            <tr>
                              <th className="py-2.5 px-6">Rank</th>
                              <th className="py-2.5 px-4">Feature Name</th>
                              <th className="py-2.5 px-4 text-right">Raw Telemetry</th>
                              <th className="py-2.5 px-4 text-right">Model Input</th>
                              <th className="py-2.5 px-4 text-right">SHAP Value</th>
                              <th className="py-2.5 px-6 text-center">Directional Impact</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {shapData.map((row, idx) => (
                              <tr key={row.rawKey} className="hover:bg-slate-50/60">
                                <td className="py-2.5 px-6 font-mono text-slate-400">{idx + 1}</td>
                                <td className="py-2.5 px-4 font-medium text-slate-900">{row.name}</td>
                                <td className="py-2.5 px-4 text-right font-mono text-slate-600">
                                  {row.original_value}
                                </td>
                                <td className="py-2.5 px-4 text-right font-mono text-slate-900 font-semibold">
                                  {row.model_input_value}
                                </td>
                                <td className="py-2.5 px-4 text-right font-mono font-bold">
                                  <span className={row.shap_value >= 0 ? 'text-rose-600' : 'text-emerald-600'}>
                                    {row.shap_value > 0 ? `+${row.shap_value}` : row.shap_value}
                                  </span>
                                </td>
                                <td className="py-2.5 px-6 text-center">
                                  {row.shap_value > 0 ? (
                                    <span className="inline-flex items-center gap-1 rounded-full bg-rose-50 px-2 py-0.5 text-[11px] font-semibold text-rose-700">
                                      <ArrowUpRight className="h-3 w-3" /> Increases Risk
                                    </span>
                                  ) : row.shap_value < 0 ? (
                                    <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold text-emerald-700">
                                      <ArrowDownRight className="h-3 w-3" /> Mitigates Risk
                                    </span>
                                  ) : (
                                    <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-semibold text-slate-600">
                                      <Minus className="h-3 w-3" /> Neutral
                                    </span>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* Scientific Disclaimer */}
                  <div className="rounded-xl border border-amber-200 bg-amber-50/60 p-4 text-xs text-amber-900 leading-relaxed space-y-1">
                    <div className="font-semibold text-slate-800 flex items-center gap-1.5">
                      <Info className="h-4 w-4 text-amber-700" />
                      Mathematical Interpretability Note & Demonstration Limitations
                    </div>
                    <p>
                      <strong>Statistical Risk Model:</strong> This machine learning model provides secondary statistical risk intelligence based on Mail Rakhwala baseline telemetry and behavioral patterns.
                    </p>
                    <p>
                      SHAP values describe additive feature attributions for tree ensembles via Shapley cooperative game theory. They indicate how features push model margins relative to base expectations; they do not represent empirical attack causality or exploit success probabilities. Deterministic RFC compliance evaluation remains authoritative.
                    </p>
                  </div>
                </>
              ) : (
                <div className="rounded-2xl border border-[#E5E5E0] bg-[#F7F7F5] p-6 shadow-sm">
                  <div className="flex items-start gap-4">
                    <div className="mt-1 flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-[#111111] text-white">
                      <Info className="h-6 w-6" />
                    </div>
                    <div>
                      <h3 className="text-base font-bold text-slate-900">
                        ML inference unavailable: {shap?.reason || 'risk_model_unavailable'}
                      </h3>
                      <p className="mt-1 text-xs text-slate-600 leading-relaxed max-w-3xl">
                        SHAP local feature attribution requires a fitted XGBoost classification model ({shap?.reason ? shap.reason.replace(/_/g, ' ') : 'risk model unavailable'}).
                        Deterministic RFC compliance findings and cryptographic posture audits are 100% active.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 5: THREAT CONTEXT (MITRE ATT&CK) */}
          {activeTab === 'threats' && (
            <div className="space-y-6">
              {threats.length === 0 ? (
                <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center shadow-sm">
                  <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-slate-100 text-slate-500">
                    <Dna className="h-6 w-6" />
                  </div>
                  <h3 className="mt-4 text-base font-bold text-slate-900">
                    No threat-context mapping was returned by the analysis engine.
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
                        value={threatSearch}
                        onChange={(e) => setThreatSearch(e.target.value)}
                        className="w-full pl-9 pr-4 py-2 text-xs rounded-xl border border-slate-200 bg-white focus:outline-none focus:ring-2 focus:ring-[#111111]/20 focus:border-[#111111]"
                      />
                    </div>

                    <div className="flex items-center gap-2">
                      <Filter className="h-4 w-4 text-slate-400 shrink-0" />
                      <select
                        value={threatCategory}
                        onChange={(e) => setThreatCategory(e.target.value)}
                        className="text-xs rounded-xl border border-slate-200 bg-white px-3 py-2 text-slate-700 focus:outline-none focus:ring-2 focus:ring-[#111111]/20 focus:border-[#111111]"
                      >
                        <option value="ALL">All Categories ({threats.length})</option>
                        {threatCategories.map((cat) => (
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
          )}

          {/* TAB 6: VULNERABILITY / CVE INTELLIGENCE */}
          {activeTab === 'vulnerabilities' && (
            <div className="space-y-6">
              {vulnerabilities.length === 0 ? (
                <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center shadow-sm">
                  <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-slate-100 text-slate-500">
                    <Bug className="h-6 w-6" />
                  </div>
                  <h3 className="mt-4 text-base font-bold text-slate-900">
                    No vulnerability mappings returned.
                  </h3>
                  <p className="mt-1 text-xs text-slate-500 max-w-md mx-auto">
                    No observed cryptographic parameters or protocol deficiencies met the criteria for deterministic CWE or CVE correlation.
                  </p>
                </div>
              ) : (
                <>
                  {/* Search Bar */}
                  <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                      <input
                        type="text"
                        placeholder="Search by CWE (e.g. CWE-295), CVE, title, finding ID..."
                        value={vulnSearch}
                        onChange={(e) => setVulnSearch(e.target.value)}
                        className="w-full pl-9 pr-4 py-2 text-xs rounded-xl border border-slate-200 bg-white focus:outline-none focus:ring-2 focus:ring-[#111111]/20 focus:border-[#111111]"
                      />
                    </div>
                  </div>

                  {/* Vulnerability Cards */}
                  <div className="space-y-4">
                    {filteredVulns.length === 0 ? (
                      <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center text-slate-500 text-sm">
                        No vulnerability mappings match your search query.
                      </div>
                    ) : (
                      filteredVulns.map((v) => {
                        const isExpanded = expandedVuln === v.mapping_id;
                        return (
                          <div
                            key={v.mapping_id}
                            className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm hover:border-purple-200 transition-all space-y-3"
                          >
                            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                              <div className="space-y-2 flex-1">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="font-mono text-xs font-black text-purple-800 bg-purple-50 border border-purple-200/60 px-2.5 py-0.5 rounded-md">
                                    {v.identifier}
                                  </span>
                                  {v.vulnerability_id && (
                                    <span className="font-mono text-xs font-black text-red-800 bg-red-50 border border-red-200/60 px-2.5 py-0.5 rounded-md">
                                      {v.vulnerability_id}
                                    </span>
                                  )}
                                  <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
                                    {safeVal(v.category, 'GENERAL').replace(/_/g, ' ')}
                                  </span>
                                  <span className="text-xs font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded">
                                    Confidence: {v.confidence}
                                  </span>
                                </div>

                                <h3 className="text-base font-bold text-slate-900">
                                  {v.title}
                                </h3>

                                <p className="text-xs text-slate-600 leading-relaxed max-w-4xl">
                                  {v.description}
                                </p>

                                <div className="text-xs text-slate-500 pt-1">
                                  Source Finding: <strong className="text-[#111111] font-mono">{v.source_finding_id}</strong>
                                </div>
                              </div>

                              <button
                                onClick={() => setExpandedVuln(isExpanded ? null : v.mapping_id)}
                                className="text-xs font-semibold text-purple-700 hover:text-purple-800 flex items-center gap-1 px-3 py-1.5 rounded-lg bg-purple-50 hover:bg-purple-100 transition-colors shrink-0"
                              >
                                {isExpanded ? 'Hide Details' : 'View Rationale'}
                                <ArrowRight className={`h-3.5 w-3.5 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                              </button>
                            </div>

                            {/* Expandable Details Drawer */}
                            {isExpanded && (
                              <div className="pt-3 border-t border-slate-100 bg-slate-50/70 rounded-xl p-4 text-xs space-y-3">
                                <div>
                                  <span className="font-semibold text-slate-800 uppercase tracking-wider text-[10px] block mb-1">
                                    Mapping Rationale
                                  </span>
                                  <p className="text-slate-700 leading-relaxed bg-white p-3 rounded-lg border border-slate-200 font-mono text-[11px]">
                                    {v.rationale}
                                  </p>
                                </div>

                                {v.references && v.references.length > 0 && (
                                  <div className="flex items-center gap-2 flex-wrap text-[11px] text-slate-500">
                                    <span className="font-semibold text-slate-700">References:</span>
                                    {v.references.map((ref, idx) => (
                                      <span key={idx} className="font-mono bg-white border border-slate-200 px-2 py-0.5 rounded">
                                        {ref}
                                      </span>
                                    ))}
                                  </div>
                                )}

                                {v.evidence && (
                                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-slate-700 pt-2 border-t border-slate-200">
                                    <div>
                                      <span className="text-slate-400 block text-[11px]">Observed Property</span>
                                      <span className="font-mono font-medium">{v.evidence.observed_property}</span>
                                    </div>
                                    <div>
                                      <span className="text-slate-400 block text-[11px]">Observed Value</span>
                                      <span className="font-mono font-bold text-slate-900">{String(v.evidence.observed_value)}</span>
                                    </div>
                                    <div>
                                      <span className="text-slate-400 block text-[11px]">Reference Standard</span>
                                      <span className="font-mono">{String(v.evidence.reference_value)}</span>
                                    </div>
                                  </div>
                                )}
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
          )}
        </>
      )}
    </div>
  );
}
