import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

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

export const checkHealth = async () => {
  const response = await apiClient.get('/health');
  return response.data;
};

export const getHealth = checkHealth;

export const uploadCapture = async (file) => {
  const formData = new FormData();
  formData.append('file', file);

  const response = await apiClient.post('/analysis/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};

export const getAnalysisJob = async (analysisId) => {
  const response = await apiClient.get(`/analysis/${analysisId}`);
  return response.data;
};

export const getAnalysisReport = async (analysisId) => {
  const response = await apiClient.get(`/analysis/${analysisId}/report`);
  return response.data;
};

export const exportReportPDFUrl = (analysisId) => {
  return `${API_BASE_URL}/analysis/${analysisId}/report/pdf`;
};

export default apiClient;