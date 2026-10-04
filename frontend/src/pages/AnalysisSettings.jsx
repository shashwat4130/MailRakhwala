import React, { useState, useEffect } from 'react';
import {
  Settings,
  Sliders,
  Database,
  Shield,
  Layers,
  CheckCircle2,
  AlertCircle,
  RotateCcw,
  Save,
  Info,
} from 'lucide-react';
import { useAnalysis } from '../hooks/useAnalysis';
import PageHeader from '../components/PageHeader';
import { safeVal } from '../utils/formatters';

export default function AnalysisSettings() {
  const { analysisId, setAnalysisId, report, reload, loading } = useAnalysis();

  // Frontend-only preferences (stored in localStorage)
  const [sessionInput, setSessionInput] = useState(analysisId || '');
  const [defaultSeverityFilter, setDefaultSeverityFilter] = useState(
    () => localStorage.getItem('mr_pref_severity_filter') || 'ALL'
  );
  const [tableDensity, setTableDensity] = useState(
    () => localStorage.getItem('mr_pref_table_density') || 'comfortable'
  );
  const [savedNotification, setSavedNotification] = useState(false);

  useEffect(() => {
    if (analysisId) {
      setSessionInput(analysisId);
    }
  }, [analysisId]);

  const handleSavePreferences = (e) => {
    e.preventDefault();
    localStorage.setItem('mr_pref_severity_filter', defaultSeverityFilter);
    localStorage.setItem('mr_pref_table_density', tableDensity);
    setSavedNotification(true);
    setTimeout(() => setSavedNotification(false), 3000);
  };

  const handleSwitchSession = (e) => {
    e.preventDefault();
    if (sessionInput.trim() && sessionInput.trim() !== analysisId) {
      setAnalysisId(sessionInput.trim());
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <PageHeader
        category="SYSTEM"
        title="Analysis Settings"
        description="Frontend console preferences, active session identifier management, and authoritative cryptographic engine parameters."
        onRefresh={reload}
        isRefreshing={loading}
      />

      {savedNotification && (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50/70 p-4 flex items-center gap-2 text-xs text-emerald-800">
          <CheckCircle2 className="h-4 w-4 text-emerald-600" />
          <span>Console preferences saved to browser storage.</span>
        </div>
      )}

      {/* Grid: Console Preferences + Active Session Switcher */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Active Session Management */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
          <form onSubmit={handleSwitchSession} className="space-y-4">
            <div className="flex items-center gap-2">
              <Database className="h-5 w-5 text-[#111111]" />
              <h3 className="text-base font-bold text-slate-900">Active Analysis Session</h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Switch the active investigation console to a previously executed session ID.
              The report will be retrieved directly from local storage or cached API data.
            </p>

            <div className="space-y-1.5">
              <label className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                Session Identifier (UUID)
              </label>
              <input
                type="text"
                value={sessionInput}
                onChange={(e) => setSessionInput(e.target.value)}
                placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000"
                className="w-full px-3 py-2 text-xs font-mono rounded-xl border border-slate-200 bg-slate-50/50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-[#111111]/20 focus:border-[#111111]"
              />
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] text-slate-400 font-mono">
                Current: {analysisId ? analysisId.slice(0, 8) + '...' : 'None'}
              </span>
              <button
                type="submit"
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[#111111] text-white text-xs font-semibold hover:bg-[#222222] shadow-sm transition-all"
              >
                Switch Session
              </button>
            </div>
          </form>

          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
            <span>Session Status: <strong className="text-slate-900">{report?.session?.status || 'IDLE'}</strong></span>
            <span>Streams: <strong className="text-slate-900">{report?.session?.total_streams || 0}</strong></span>
          </div>
        </div>

        {/* UI / Display Preferences */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
          <form onSubmit={handleSavePreferences} className="space-y-4">
            <div className="flex items-center gap-2">
              <Sliders className="h-5 w-5 text-indigo-600" />
              <h3 className="text-base font-bold text-slate-900">Console Display Preferences</h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Customize client-side view options. Preferences are persisted locally in your browser
              and do not modify backend behavior.
            </p>

            <div className="space-y-3">
              <div>
                <label className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                  Default Findings Filter
                </label>
                <select
                  value={defaultSeverityFilter}
                  onChange={(e) => setDefaultSeverityFilter(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-slate-200 bg-white text-slate-700 focus:outline-none focus:ring-2 focus:ring-[#111111]/20 focus:border-[#111111]"
                >
                  <option value="ALL">Show All Findings</option>
                  <option value="HIGH_CRITICAL">High & Critical Only</option>
                  <option value="NON_COMPLIANT">Non-Compliant Only</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                  Table Layout Density
                </label>
                <select
                  value={tableDensity}
                  onChange={(e) => setTableDensity(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-slate-200 bg-white text-slate-700 focus:outline-none focus:ring-2 focus:ring-[#111111]/20 focus:border-[#111111]"
                >
                  <option value="comfortable">Comfortable (Standard)</option>
                  <option value="compact">Compact (High Information Density)</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-end pt-2">
              <button
                type="submit"
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-900 text-white text-xs font-semibold hover:bg-slate-800 shadow-sm transition-all"
              >
                <Save className="h-3.5 w-3.5" /> Save Preferences
              </button>
            </div>
          </form>

          <div className="mt-6 pt-4 border-t border-slate-100 text-[11px] text-slate-400">
            Stored in browser localStorage under key: mr_pref_*
          </div>
        </div>
      </div>

      {/* Read-Only Engine Parameters */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-100 pb-4">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-[#111111]" />
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Authoritative Engine Specifications (Read-Only)
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Backend parameters governing deterministic scoring, rule catalogs, and ML pipelines
              </p>
            </div>
          </div>
          <span className="text-[11px] font-mono bg-slate-100 text-slate-700 px-2.5 py-1 rounded font-bold">
            FROZEN / READ-ONLY
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="rounded-xl border border-slate-100 bg-slate-50/70 p-4 space-y-1">
            <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-400">
              Conformance Standards
            </span>
            <div className="font-semibold text-slate-800">
              RFC 8314, RFC 3207, RFC 7525
            </div>
            <p className="text-[11px] text-slate-500 pt-1">
              Enforces explicit TLS in mail transport, mandatory forward secrecy, and SHA-2 signatures.
            </p>
          </div>

          <div className="rounded-xl border border-slate-100 bg-slate-50/70 p-4 space-y-1">
            <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-400">
              Posture Scoring Baseline
            </span>
            <div className="font-semibold text-slate-800">
              Base: 100 pts | Deterministic Waterfall
            </div>
            <p className="text-[11px] text-slate-500 pt-1">
              Zero-tolerance deduction model without statistical fuzzing or heuristic variance.
            </p>
          </div>

          <div className="rounded-xl border border-slate-100 bg-slate-50/70 p-4 space-y-1">
            <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-400">
              ML Feature Space
            </span>
            <div className="font-semibold text-slate-800">
              19-Dimensional Deterministic Vector
            </div>
            <p className="text-[11px] text-slate-500 pt-1">
              Encodes TLS protocol parameters, PKI trust states, and policy violations into tabular vectors.
            </p>
          </div>
        </div>

        <div className="rounded-xl border border-[#E5E5E0] bg-[#F7F7F5] p-4 text-xs text-[#111111] flex items-start gap-2.5">
          <Info className="h-4 w-4 text-[#111111] shrink-0 mt-0.5" />
          <span>
            Backend configuration is immutably defined by security policy rules. To alter rule thresholds
            or scoring penalties, authoritative backend configuration files must be updated by system administrators.
          </span>
        </div>
      </div>
    </div>
  );
}
