/**
 * Formatters and data serialization helpers for MailRakhwala.
 */

export const formatBytes = (bytes, decimals = 1) => {
  if (bytes === null || bytes === undefined || isNaN(bytes)) return '0 B';
  if (bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
};

export const formatTimestamp = (ts) => {
  if (!ts) return 'Not recorded';
  try {
    if (typeof ts === 'number') {
      const d = ts < 1e11 ? new Date(ts * 1000) : new Date(ts);
      return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    }
    const d = new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  } catch {
    return String(ts);
  }
};

export const formatUtcTimestamp = formatTimestamp;

export const valueOrUnavailable = (value, fallback = 'Unavailable from captured evidence') => {
  if (value === null || value === undefined || value === '') {
    return fallback;
  }
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
};

export const safeVal = (value, fallback = 'Unavailable') => {
  return valueOrUnavailable(value, fallback);
};

export const downloadBlob = (blob, filename) => {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
};

export const downloadJson = (data, filename = 'MailRakhwala_Export.json') => {
  const jsonStr = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  downloadBlob(blob, filename);
};

export const exportToCsv = (arg1, arg2, headers) => {
  let filename = 'export.csv';
  let rows = [];

  if (Array.isArray(arg1)) {
    rows = arg1;
    filename = arg2 || 'export.csv';
  } else {
    filename = arg1 || 'export.csv';
    rows = arg2 || [];
  }

  if (!rows || !rows.length) return;

  const headerKeys = headers
    ? headers.map((h) => (typeof h === 'string' ? h : h.key))
    : Object.keys(rows[0] || {});

  const headerLabels = headers
    ? headers.map((h) => (typeof h === 'string' ? h : h.label))
    : headerKeys.map((k) => k.replace(/_/g, ' ').toUpperCase());

  const csvRows = [];
  csvRows.push(headerLabels.map((l) => `"${String(l).replace(/"/g, '""')}"`).join(','));

  for (const row of rows) {
    const values = headerKeys.map((key) => {
      let val = row[key];
      if (val === null || val === undefined) val = '';
      else if (typeof val === 'object') val = JSON.stringify(val);
      else val = String(val);
      return `"${val.replace(/"/g, '""')}"`;
    });
    csvRows.push(values.join(','));
  }

  const csvString = csvRows.join('\r\n');
  const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
  downloadBlob(blob, filename);
};
