/**
 * Severity and Compliance status visual mapping utilities.
 */

export const normalizeSeverity = (severity) => {
  const s = String(severity || '').trim().toUpperCase();
  if (s === 'CRITICAL') return 'CRITICAL';
  if (s === 'HIGH') return 'HIGH';
  if (s === 'MEDIUM') return 'MEDIUM';
  if (s === 'LOW') return 'LOW';
  if (s === 'INFO' || s === 'INFORMATIONAL') return 'INFO';
  return 'UNKNOWN';
};

export const normalizeStatus = (status) => {
  const s = String(status || '').trim().toUpperCase();
  if (s === 'NON_COMPLIANT' || s === 'FAIL') return 'NON_COMPLIANT';
  if (s === 'COMPLIANT' || s === 'PASS') return 'COMPLIANT';
  if (s === 'UNKNOWN') return 'UNKNOWN';
  if (s === 'NOT_APPLICABLE' || s === 'NA') return 'NOT_APPLICABLE';
  return s || 'UNKNOWN';
};

export const severityBadgeClasses = (severity) => {
  switch (normalizeSeverity(severity)) {
    case 'CRITICAL':
      return 'border border-red-200 bg-red-50 text-red-700';
    case 'HIGH':
      return 'border border-orange-200 bg-orange-50 text-orange-700';
    case 'MEDIUM':
      return 'border border-amber-200 bg-amber-50 text-amber-700';
    case 'LOW':
      return 'border border-slate-200 bg-slate-100 text-slate-700';
    case 'INFO':
      return 'border border-blue-200 bg-blue-50 text-blue-700';
    default:
      return 'border border-slate-200 bg-slate-50 text-slate-600';
  }
};

export const severityDotClasses = (severity) => {
  switch (normalizeSeverity(severity)) {
    case 'CRITICAL':
      return 'bg-red-500';
    case 'HIGH':
      return 'bg-orange-500';
    case 'MEDIUM':
      return 'bg-amber-500';
    case 'LOW':
      return 'bg-slate-400';
    case 'INFO':
      return 'bg-blue-500';
    default:
      return 'bg-slate-400';
  }
};

export const statusBadgeClasses = (status) => {
  switch (normalizeStatus(status)) {
    case 'NON_COMPLIANT':
      return 'border border-red-200 bg-red-50 text-red-700';
    case 'COMPLIANT':
      return 'border border-emerald-200 bg-emerald-50 text-emerald-700';
    case 'UNKNOWN':
      return 'border border-amber-200 bg-amber-50 text-amber-700';
    case 'NOT_APPLICABLE':
      return 'border border-slate-200 bg-slate-100 text-slate-600';
    default:
      return 'border border-blue-200 bg-blue-50 text-blue-700';
  }
};

export const getSeverityBadge = (severity) => ({
  badge: severityBadgeClasses(severity),
  dot: severityDotClasses(severity),
});

export const getStatusBadge = (status) => ({
  badge: statusBadgeClasses(status),
});

export const getScoreTone = (score) => {
  if (score === null || score === undefined) return { tone: 'slate', label: 'Not Assessed', bg: 'bg-slate-100 text-slate-700 border-slate-200' };
  if (score >= 80) return { tone: 'emerald', label: 'Strong Posture', bg: 'bg-emerald-50 text-emerald-700 border-emerald-200' };
  if (score >= 60) return { tone: 'amber', label: 'Moderate Risk', bg: 'bg-amber-50 text-amber-700 border-amber-200' };
  if (score >= 30) return { tone: 'orange', label: 'High Risk', bg: 'bg-orange-50 text-orange-700 border-orange-200' };
  return { tone: 'red', label: 'Critical Risk', bg: 'bg-red-50 text-red-700 border-red-200' };
};

export const getScoreColor = (score) => {
  const tone = getScoreTone(score);
  let text = 'text-slate-900';
  if (score !== null && score !== undefined) {
    if (score >= 80) text = 'text-emerald-600';
    else if (score >= 60) text = 'text-blue-600';
    else if (score >= 30) text = 'text-amber-600';
    else text = 'text-rose-600';
  }
  return { ...tone, text };
};

export const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#64748b',
  INFO: '#3b82f6',
};

export const STATUS_COLORS = {
  COMPLIANT: '#10b981',
  NON_COMPLIANT: '#ef4444',
  UNKNOWN: '#f59e0b',
  NOT_APPLICABLE: '#94a3b8',
};
