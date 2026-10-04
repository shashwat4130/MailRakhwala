import React, {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  useRef,
} from 'react';
import {
  getActiveAnalysisId,
  setActiveAnalysisId,
  getAnalysisReport,
} from '../services/api';
import { normalizeReport } from '../utils/reportModel';

export const AnalysisContext = createContext({
  analysisId: null,
  report: null,
  loading: false,
  error: null,
  processingStatus: null,
  setAnalysisId: () => {},
  reload: async () => {},
  clear: () => {},
});

const POLL_INTERVAL_MS = 1500;
const MAX_ATTEMPTS = 40; // Up to 60 seconds of polling

export function AnalysisProvider({ children }) {
  const resolveCurrentId = () =>
    getActiveAnalysisId() ||
    localStorage.getItem('active_analysis_id') ||
    localStorage.getItem('analysis_id') ||
    null;

  const [analysisId, setAnalysisIdState] = useState(resolveCurrentId);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [processingStatus, setProcessingStatus] = useState(null);

  const activePollingRef = useRef(null);

  const fetchReport = useCallback(async (id) => {
    // Cancel any ongoing polling routine
    if (activePollingRef.current) {
      activePollingRef.current.cancelled = true;
    }

    if (!id) {
      setReport(null);
      setError(null);
      setLoading(false);
      setProcessingStatus(null);
      return;
    }

    const currentPolling = { cancelled: false };
    activePollingRef.current = currentPolling;

    // Reset report to prevent stale state leakage while loading
    setReport(null);
    setLoading(true);
    setError(null);
    setProcessingStatus('Connecting to analysis engine...');

    let attempts = 0;

    while (!currentPolling.cancelled && attempts < MAX_ATTEMPTS) {
      attempts++;
      try {
        const data = await getAnalysisReport(id);

        if (currentPolling.cancelled) return;

        setReport(normalizeReport(data));
        setError(null);
        setLoading(false);
        setProcessingStatus(null);
        return;
      } catch (err) {
        if (currentPolling.cancelled) return;

        const statusCode = err?.response?.status;

        // 409 Conflict: Analysis is queued or still processing
        if (statusCode === 409) {
          const detailMsg =
            err?.response?.data?.detail ||
            'Analysis is processing... Evaluating protocol telemetry';
          setProcessingStatus(detailMsg);
          // Wait before the next poll
          await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
          continue;
        }

        // 404 Not Found: Analysis ID does not exist in store
        if (statusCode === 404) {
          setError(
            err?.response?.data?.detail ||
            'Analysis session not found. Please upload a PCAP capture.'
          );
          setReport(null);
          setLoading(false);
          setProcessingStatus(null);
          return;
        }

        // Handle initial network latency/transient disconnects
        if (attempts < 3 && (!err?.response || err.code === 'ERR_NETWORK')) {
          setProcessingStatus('Waiting for backend response...');
          await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
          continue;
        }

        // Terminal error
        console.error('Failed to load analysis report in AnalysisContext:', err);
        setError(
          err?.response?.data?.detail ||
          err?.message ||
          'The security report could not be loaded.'
        );
        setReport(null);
        setLoading(false);
        setProcessingStatus(null);
        return;
      }
    }

    // Polling timeout exceeded
    if (!currentPolling.cancelled && attempts >= MAX_ATTEMPTS) {
      setError(
        'Analysis timed out while processing. The capture may be unusually large or backend processing is delayed. Please retry.'
      );
      setReport(null);
      setLoading(false);
      setProcessingStatus(null);
    }
  }, []);

  useEffect(() => {
    fetchReport(analysisId);

    return () => {
      if (activePollingRef.current) {
        activePollingRef.current.cancelled = true;
      }
    };
  }, [analysisId, fetchReport]);

  useEffect(() => {
    const handleIdChange = () => {
      const newId = resolveCurrentId();
      setAnalysisIdState(newId);
    };

    window.addEventListener('analysisIdChanged', handleIdChange);
    window.addEventListener('storage', handleIdChange);

    return () => {
      window.removeEventListener('analysisIdChanged', handleIdChange);
      window.removeEventListener('storage', handleIdChange);
    };
  }, []);

  const changeAnalysisId = useCallback((id) => {
    setActiveAnalysisId(id);
    setAnalysisIdState(id);
  }, []);

  const reload = useCallback(() => {
    const currentId = resolveCurrentId();
    return fetchReport(currentId);
  }, [fetchReport]);

  const clear = useCallback(() => {
    if (activePollingRef.current) {
      activePollingRef.current.cancelled = true;
    }
    setActiveAnalysisId(null);
    setAnalysisIdState(null);
    setReport(null);
    setError(null);
    setLoading(false);
    setProcessingStatus(null);
  }, []);

  return (
    <AnalysisContext.Provider
      value={{
        analysisId,
        report,
        loading,
        error,
        processingStatus,
        setAnalysisId: changeAnalysisId,
        reload,
        clear,
      }}
    >
      {children}
    </AnalysisContext.Provider>
  );
}

export const useAnalysisContext = () => useContext(AnalysisContext);
