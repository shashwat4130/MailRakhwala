import React, { useMemo } from 'react';
import {
  Brain,
  Layers,
  Cpu,
  Info,
  AlertTriangle,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
  FileSearch,
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
import { safeVal } from '../utils/formatters';

export default function MLExplainability() {
  const { report, loading, error, reload, analysisId } = useAnalysis();

  const shap = report?.shap_explanation;
  const featureVector = report?.feature_vector;
  const isShapAvailable = shap && shap.available !== false && Boolean(shap.predicted_class || shap.prediction);

  // Chart data from SHAP contributions
  const chartData = useMemo(() => {
    if (!isShapAvailable || !shap?.feature_contributions) return [];
    // Sort by absolute SHAP value descending
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

  if (!analysisId) {
    return <EmptyAnalysisState title="ML Explainability" />;
  }

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <PageHeader
        category="INTELLIGENCE"
        title="ML Explainability"
        description="Local SHAP (SHapley Additive exPlanations) TreeExplainer feature attributions explaining the exact mathematical influence of each parameter."
        onRefresh={reload}
        isRefreshing={loading}
      />

      {loading && !report ? (
        <LoadingState
          title="SHAP Explainability Engine"
          message="Calculating local Shapley values and TreeExplainer mathematical attributions..."
        />
      ) : error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50/50 p-6 text-red-700">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-6 w-6 text-red-600" />
            <span className="font-semibold">Failed to load SHAP explanations</span>
          </div>
          <p className="mt-2 text-sm text-red-600">{error}</p>
        </div>
      ) : (
        <>
          {/* Top Status & Architecture Banner */}
          {isShapAvailable ? (
            <div className="rounded-2xl border border-[#202020] bg-[#111111] p-6 shadow-sm text-white">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="flex items-start gap-4">
                  <div className="mt-1 flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-[#222222] text-white">
                    <Brain className="h-6 w-6" />
                  </div>
                  <div>
                    <div className="flex items-center gap-3 flex-wrap">
                      <h2 className="text-xl font-bold text-white">
                        Local Feature Attribution Ready
                      </h2>
                      <span className="inline-flex items-center rounded-full bg-[#222222] border border-[#333333] text-white px-2.5 py-0.5 text-xs font-semibold">
                        Target Class: {shap.predicted_class}
                      </span>
                      <span className="inline-flex items-center rounded-full bg-[#222222] border border-[#333333] text-white px-2.5 py-0.5 text-xs font-semibold">
                        Statistical Risk Model
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-white/70 leading-relaxed max-w-3xl">
                      {safeVal(shap.status_text, 'SHAP local explanations quantify the contribution of each network feature.')}
                    </p>
                  </div>
                </div>

                <div className="flex flex-col items-end shrink-0 border-t md:border-t-0 md:border-l border-[#333333] pt-3 md:pt-0 md:pl-6">
                  <span className="text-xs uppercase font-semibold text-white/60">
                    Explainer Engine
                  </span>
                  <span className="text-lg font-bold text-white font-mono mt-0.5">
                    {shap.model_metadata?.explainer_name || 'TreeExplainer'}
                  </span>
                  <span className="text-[11px] text-white/50">
                    Base Value (Margin): {typeof shap.model_metadata?.base_value === 'number' ? shap.model_metadata.base_value.toFixed(3) : '0.000'}
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

          {/* SHAP Feature Attribution Waterfall Chart */}
          {chartData.length > 0 && (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-bold text-slate-900">
                    SHAP Feature Contribution Rankings
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Positive SHAP values push towards the predicted class; negative values push away
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
                    data={chartData}
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
                      {chartData.map((entry, index) => (
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
          {chartData.length > 0 && (
            <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden">
              <div className="border-b border-slate-100 bg-slate-50/75 px-6 py-4 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileSearch className="h-4 w-4 text-slate-600" />
                  <h3 className="text-sm font-bold text-slate-800">
                    Complete Feature Attribution Table
                  </h3>
                </div>
                <span className="text-xs font-mono text-slate-500">
                  {chartData.length} Dimensions Analyzed
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
                    {chartData.map((row, idx) => (
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
      )}
    </div>
  );
}
