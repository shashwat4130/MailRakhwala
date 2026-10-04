import { useAnalysisContext } from '../context/AnalysisContext';

/**
 * Hook providing access to the centralized MailRakhwala analysis state.
 */
export function useAnalysis() {
  return useAnalysisContext();
}

export default useAnalysis;
