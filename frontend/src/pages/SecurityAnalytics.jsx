import React, { useMemo } from 'react';
import {
  BarChart3,
  PieChart as PieChartIcon,
  ShieldAlert,
  AlertTriangle,
  Layers,
  Activity,
  Dna,
  Bug,
  CheckCircle2,
  TrendingDown,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
} from 'recharts';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import EmptyAnalysisState from '../components/EmptyAnalysisState';
import { LoadingState } from '../components/LoadingScreen';
import { SEVERITY_COLORS, STATUS_COLORS } from '../utils/severity';
import { safeVal } from '../utils/formatters';

const CHART_COLORS = ['#111111', '#262626', '#404040', '#525252', '#737373', '#a3a3a3', '#d4d4d4'];

export default function SecurityAnalytics() {
  const { report, loading, error, reload, analysisId } = useAnalysis();

  const findings = report?.compliance_findings || [];
  const posture = report?.posture_report;
  const deductions = posture?.deductions || [];
  const vulnerabilities = report?.vulnerability_mappings || [];
  const threats = report?.threat_mappings || [];

  // 1. Findings by Severity
  const severityData = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach((f) => {
      const sev = f.severity?.toUpperCase() || 'INFO';
      if (counts[sev] !== undefined) counts[sev]++;
      else counts.INFO++;
    });
    return Object.entries(counts)
      .filter(([_, count]) => count > 0)
      .map(([name, count]) => ({
        name,
        count,
        color: SEVERITY_COLORS[name] || '#64748b',
      }));
  }, [findings]);

  // 2. Findings by Category
  const categoryData = useMemo(() => {
    const counts = {};
    findings.forEach((f) => {
      const cat = f.category?.replace(/_/g, ' ') || 'General';
      counts[cat] = (counts[cat] || 0) + 1;
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([name, count], index) => ({
        name,
        count,
        color: CHART_COLORS[index % CHART_COLORS.length],
      }));
  }, [findings]);

  // 3. Compliance Status Distribution
  const statusData = useMemo(() => {
    const counts = { COMPLIANT: 0, NON_COMPLIANT: 0, UNKNOWN: 0, NOT_APPLICABLE: 0 };
    findings.forEach((f) => {
      const st = f.status || 'UNKNOWN';
      if (counts[st] !== undefined) counts[st]++;
      else counts.UNKNOWN++;
    });
    return Object.entries(counts)
      .filter(([_, count]) => count > 0)
      .map(([name, count]) => ({
        name: name.replace(/_/g, ' '),
        rawKey: name,
        count,
        color: STATUS_COLORS[name] || '#94a3b8',
      }));
  }, [findings]);

  // 4. Deduction Penalties by Upstream Rule
  const deductionData = useMemo(() => {
    return deductions.map((d) => ({
      name: d.rule_id,
      penalty: d.penalty,
      title: d.title,
    }));
  }, [deductions]);

  if (!analysisId) {
    return <EmptyAnalysisState title="Security Analytics" />;
  }

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <PageHeader
        category="INTELLIGENCE"
        title="Security Analytics"
        description="Consolidated statistical dashboards visualizing compliance posture, severity breakdown, and threat distributions."
        onRefresh={reload}
        isRefreshing={loading}
      />

      {loading && !report ? (
        <LoadingState
          title="Security Analytics Telemetry"
          message="Aggregating compliance posture, severity distributions, and metric waterfalls..."
        />
      ) : error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50/50 p-6 text-red-700">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-6 w-6 text-red-600" />
            <span className="font-semibold">Failed to load analytics</span>
          </div>
          <p className="mt-2 text-sm text-red-600">{error}</p>
        </div>
      ) : (
        <>
          {/* Top Aggregation Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
              <span className="text-[11px] font-extrabold uppercase tracking-wider text-slate-400">
                Total Evaluated Rules
              </span>
              <div className="mt-2 text-3xl font-black text-slate-900 font-mono">
                {findings.length}
              </div>
              <div className="mt-1 text-xs text-slate-500">RFC compliance evaluations</div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
              <span className="text-[11px] font-extrabold uppercase tracking-wider text-slate-400">
                Deductions Applied
              </span>
              <div className="mt-2 text-3xl font-black text-rose-600 font-mono">
                -{posture?.total_penalty ?? 0}
              </div>
              <div className="mt-1 text-xs text-slate-500">{deductions.length} penalty rules triggered</div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
              <span className="text-[11px] font-extrabold uppercase tracking-wider text-slate-400">
                Mapped Weaknesses
              </span>
              <div className="mt-2 text-3xl font-black text-amber-600 font-mono">
                {vulnerabilities.length}
              </div>
              <div className="mt-1 text-xs text-slate-500">CWE / CVE defect classifications</div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
              <span className="text-[11px] font-extrabold uppercase tracking-wider text-slate-400">
                ATT&CK Mappings
              </span>
              <div className="mt-2 text-3xl font-black text-indigo-600 font-mono">
                {threats.length}
              </div>
              <div className="mt-1 text-xs text-slate-500">Adversarial technique contexts</div>
            </div>
          </div>

          {/* Charts Row 1: Severity Pie & Compliance Donut */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Findings by Severity */}
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-base font-bold text-slate-900">Findings by Severity</h3>
                <span className="text-xs text-slate-400 font-mono">{findings.length} Total</span>
              </div>

              {severityData.length > 0 ? (
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityData}
                        dataKey="count"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        labelLine={false}
                      >
                        {severityData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        formatter={(val, name) => [`${val} findings`, `${name} Severity`]}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="h-64 flex items-center justify-center text-slate-400 text-sm">
                  No findings recorded
                </div>
              )}
            </div>

            {/* Compliance Status Distribution */}
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-base font-bold text-slate-900">Compliance Status Distribution</h3>
                <span className="text-xs text-slate-400 font-mono">Deterministic Conformance</span>
              </div>

              {statusData.length > 0 ? (
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={statusData}
                        dataKey="count"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={4}
                        label={({ name, count }) => `${name}: ${count}`}
                      >
                        {statusData.map((entry, index) => (
                          <Cell key={`cell-status-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        formatter={(val, name) => [`${val} rules`, name]}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="h-64 flex items-center justify-center text-slate-400 text-sm">
                  No status breakdown available
                </div>
              )}
            </div>
          </div>

          {/* Charts Row 2: Findings by Category Bar Chart */}
          <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-slate-900">Findings by Category</h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Distribution of evaluated findings across security domains
                </p>
              </div>
              <span className="text-xs font-mono bg-slate-100 text-slate-700 px-2 py-1 rounded">
                {categoryData.length} Categories
              </span>
            </div>

            {categoryData.length > 0 ? (
              <div className="h-72 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={categoryData} margin={{ top: 20, right: 30, left: 20, bottom: 25 }}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                    <XAxis
                      dataKey="name"
                      stroke="#64748b"
                      fontSize={11}
                      angle={-15}
                      textAnchor="end"
                      height={40}
                    />
                    <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                    <Tooltip
                      formatter={(val, name) => [`${val} findings`, 'Total']}
                    />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {categoryData.map((entry, index) => (
                        <Cell key={`cell-cat-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-72 flex items-center justify-center text-slate-400 text-sm">
                No categorical data available
              </div>
            )}
          </div>

          {/* Charts Row 3: Deduction Waterfall */}
          {deductionData.length > 0 && (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-bold text-slate-900">Penalty Point Deductions by Rule</h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Individual penalty points subtracted from the 100-point base score
                  </p>
                </div>
                <span className="text-xs font-mono text-rose-600 bg-rose-50 px-2.5 py-1 rounded-md font-bold">
                  Total Penalty: -{posture?.total_penalty ?? 0} pts
                </span>
              </div>

              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={deductionData} margin={{ top: 10, right: 30, left: 20, bottom: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                    <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#94a3b8" fontSize={11} unit=" pts" />
                    <Tooltip
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          const item = payload[0].payload;
                          return (
                            <div className="rounded-lg border border-slate-200 bg-white p-2.5 shadow-lg text-xs">
                              <p className="font-bold text-slate-800">{item.name}</p>
                              <p className="text-slate-600">{item.title}</p>
                              <p className="text-rose-600 font-mono font-bold mt-1">
                                Penalty: -{item.penalty} pts
                              </p>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                    <Bar dataKey="penalty" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
