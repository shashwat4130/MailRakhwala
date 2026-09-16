import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

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

export default apiClient;