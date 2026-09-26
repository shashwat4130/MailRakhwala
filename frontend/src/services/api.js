import axios from 'axios';

// MailRakhwala backend
// FastAPI is running on port 8001.
const API_BASE_URL =
  import.meta.env.VITE_API_URL || 'http://127.0.0.1:8001';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const STORAGE_ANALYSIS_KEY = 'active_analysis_id';

export const getActiveAnalysisId = () => {
  return localStorage.getItem(STORAGE_ANALYSIS_KEY) || null;
};

export const setActiveAnalysisId = (id) => {
  if (id) {
    localStorage.setItem(STORAGE_ANALYSIS_KEY, id);
    window.dispatchEvent(new Event('analysisIdChanged'));
  } else {
    localStorage.removeItem(STORAGE_ANALYSIS_KEY);
    window.dispatchEvent(new Event('analysisIdChanged'));
  }
};

/**
 * Check backend health.
 */
export const checkHealth = async () => {
  const response = await apiClient.get('/health');
  return response.data;
};

export const getHealth = checkHealth;

/**
 * Upload a PCAP / PCAPNG capture.
 *
 * IMPORTANT:
 * This uses axios directly instead of apiClient because
 * the request must be multipart/form-data.
 *
 * Axios/browser will automatically set the correct
 * multipart Content-Type boundary.
 */
export const uploadCapture = async (file) => {
  if (!file) {
    throw new Error('No capture file selected.');
  }

  const formData = new FormData();

  formData.append('file', file, file.name);

  const response = await axios.post(
    `${API_BASE_URL}/analysis/upload`,
    formData
  );

  return response.data;
};

/**
 * Get the current status of an analysis job.
 */
export const getAnalysisJob = async (analysisId) => {
  if (!analysisId) {
    throw new Error('Analysis ID is required.');
  }

  const response = await apiClient.get(
    `/analysis/${analysisId}`
  );

  return response.data;
};

/**
 * Get the completed comprehensive analysis report.
 */
export const getAnalysisReport = async (analysisId) => {
  if (!analysisId) {
    throw new Error('Analysis ID is required.');
  }

  const response = await apiClient.get(
    `/analysis/${analysisId}/report`
  );

  return response.data;
};

/**
 * Return the backend URL for the PDF report.
 */
export const exportReportPDFUrl = (analysisId) => {
  if (!analysisId) {
    throw new Error('Analysis ID is required.');
  }

  return `${API_BASE_URL}/analysis/${analysisId}/report/pdf`;
};

export default apiClient;