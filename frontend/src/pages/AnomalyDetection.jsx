import React, { useMemo } from 'react';
import {
  ScanSearch,
  CheckCircle2,
  AlertTriangle,
  Info,
  Layers,
  Cpu,
  Hash,
  Activity,
  FileSearch,
  LockKeyhole,
  ShieldCheck,
  ShieldAlert,
} from 'lucide-react';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { LoadingState } from '../components/LoadingScreen';
import { safeVal } from '../utils/formatters';
import { getCanonicalFeatures, getAnomalyDetection, getFeatureVector } from '../utils/reportModel';

export default function AnomalyDetection() {
  const { report, loading, error, reload, analysisId } = useAnalysis();

  const anomaly = getAnomalyDetection(report);
  const featureVector = getFeatureVector(report);
  const canonicalFeatures = useMemo(() => getCanonicalFeatures(report), [report]);
  const isAnomalyAvailable = anomaly && anomaly.available !== false && anomaly.is_anomalous !== null && typeof anomaly.anomaly_score === 'number';

  // Group features by domain for high-fidelity technical presentation
  const groupedFeatures = useMemo(() => {
    const groups = {};
    canonicalFeatures.forEach((feat) => {
      if (!groups[feat.domain]) {
        groups[feat.domain] = [];
      }
      groups[feat.domain].push(feat);
    });
    return groups;
  }, [canonicalFeatures]);

  if (!analysisId) {
    return <EmptyAnalysisState title="Anomaly Detection" />;
  }

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <PageHeader
        category="SECURITY"
        title="Anomaly Detection"
        description="Isolation Forest unsupervised statistical outlier detection evaluating captured TLS handshakes against expected baseline distributions."
        onRefresh={reload}
        isRefreshing={loading}
      />

      {loading && !report ? (
        <LoadingState
          title="Unsupervised Anomaly Detection"
          message="Evaluating Isolation Forest outlier scores against baseline protocol distributions..."
        />
      ) : error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50/50 p-6 text-red-700">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-6 w-6 text-red-600" />
            <span className="font-semibold">Failed to load anomaly detection</span>
          </div>
          <p className="mt-2 text-sm text-red-600">{error}</p>
        </div>
      ) : (
        <>
          {/* Main Anomaly Status Banner */}
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

                {/* Score badge */}
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
              <div className="text-xs text-slate-400 mt-1">Unsupervised tree-based outlier estimator</div>
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

          {/* Grouped Feature Domains Overview */}
          {canonicalFeatures.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-slate-900">
                    Deterministic Feature Vector Domains
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    19-dimensional mathematical representation evaluated across 5 functional categories
                  </p>
                </div>
                <span className="text-xs font-mono bg-[#F7F7F5] text-[#111111] border border-[#E5E5E0] px-2.5 py-1 rounded font-semibold">
                  19 Dimensions Verified
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(groupedFeatures).map(([domain, feats]) => (
                  <div key={domain} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                      <span className="text-xs font-extrabold uppercase tracking-wider text-slate-700">
                        {domain}
                      </span>
                      <span className="text-[11px] font-mono text-slate-400 font-bold">
                        {feats.length} feat.
                      </span>
                    </div>

                    <div className="space-y-2 text-xs">
                      {feats.map((f) => (
                        <div key={f.key} className="flex items-center justify-between gap-2 py-1 border-b border-slate-50 last:border-0">
                          <span className="text-slate-600 truncate" title={f.name}>{f.name}</span>
                          <span className={`font-mono font-bold shrink-0 px-2 py-0.5 rounded text-[11px] ${
                            f.value === -1.0
                              ? 'bg-slate-100 text-slate-500'
                              : f.value === 0.0
                              ? 'bg-amber-50 text-amber-800'
                              : 'bg-emerald-50 text-emerald-800'
                          }`}>
                            {f.value}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

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
                Canonical Order (RFC 8314 & PKI Baselines)
              </span>
            </div>

            {canonicalFeatures.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-200 bg-slate-50 font-semibold text-slate-600">
                    <tr>
                      <th className="py-2.5 px-6">#</th>
                      <th className="py-2.5 px-4">Feature Name</th>
                      <th className="py-2.5 px-4 font-mono">Canonical Backend Key</th>
                      <th className="py-2.5 px-4">Domain</th>
                      <th className="py-2.5 px-4 text-right">Value</th>
                      <th className="py-2.5 px-6">Authoritative Interpretation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {canonicalFeatures.map((item) => (
                      <tr key={item.key} className="hover:bg-slate-50/60">
                        <td className="py-2.5 px-6 font-mono text-slate-400">{item.index}</td>
                        <td className="py-2.5 px-4 font-medium text-slate-900">{item.name}</td>
                        <td className="py-2.5 px-4 font-mono text-slate-500">{item.key}</td>
                        <td className="py-2.5 px-4 text-slate-500">{item.domain}</td>
                        <td className="py-2.5 px-4 text-right font-mono font-bold text-slate-900">
                          {item.value}
                        </td>
                        <td className="py-2.5 px-6 text-slate-600">
                          {item.interpretation}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-8 text-center text-sm text-slate-500">
                No feature vector recorded for this capture.
              </div>
            )}
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
        </>
      )}
    </div>
  );
}
