import React, { useState } from 'react';
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  NavLink,
} from 'react-router-dom';
import { Menu } from 'lucide-react';

import { AnalysisProvider, useAnalysisContext } from './context/AnalysisContext';
import Sidebar, { MobileSidebarDrawer } from './components/Sidebar';

// 8 Primary Pages + Ingestion & Documentation
import Home from './pages/Home';
import Dashboard from './pages/Dashboard';
import Analysis from './pages/Analysis';
import TLSAnalysis from './pages/TLSAnalysis';
import EvidenceExplorer from './pages/EvidenceExplorer';
import Findings from './pages/Findings';
import SecurityPosture from './pages/SecurityPosture';
import RiskIntelligence from './pages/RiskIntelligence';
import Reports from './pages/Reports';
import Documentation from './pages/Documentation';

/**
 * RequireAnalysisSession
 * 
 * Strict route guard for analysis-dependent features:
 * - /dashboard
 * - /analysis and /stream-analysis
 * - /tls-analysis
 * - /evidence and /evidence-explorer
 * - /findings
 * - /posture and /security-posture
 * - /risk-intelligence
 * - /reports and /forensic-reports
 * 
 * If no active session ID exists (neither in React context nor in persistent localStorage),
 * navigating to any of these routes redirects immediately to Home (/).
 * 
 * When a valid analysis session is active, the session survives browser refreshes
 * and direct URL entries.
 */
function RequireAnalysisSession({ children }) {
  const { analysisId } = useAnalysisContext();
  const storedId =
    typeof window !== 'undefined'
      ? localStorage.getItem('active_analysis_id') || localStorage.getItem('analysis_id')
      : null;

  const activeId = analysisId || storedId;

  if (!activeId) {
    return <Navigate to="/" replace />;
  }

  return children;
}

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Application ErrorBoundary caught:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-[70vh] items-center justify-center p-8 bg-white">
          <div className="max-w-md w-full rounded-3xl border border-red-200 bg-red-50/50 p-8 text-center shadow-lg">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-red-100 text-red-600 mb-4">
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <h2 className="text-xl font-bold text-slate-900 mb-2">Something went wrong loading this analysis.</h2>
            <p className="text-xs text-slate-600 mb-6 leading-relaxed">
              {this.state.error?.message || 'An unexpected rendering error occurred.'}
            </p>
            <div className="flex items-center justify-center gap-3">
              <button
                type="button"
                onClick={() => this.setState({ hasError: false, error: null })}
                className="px-4 py-2 rounded-xl bg-blue-600 text-white text-xs font-bold shadow hover:bg-blue-700 transition"
              >
                Try Again
              </button>
              <a
                href="/"
                className="px-4 py-2 rounded-xl bg-white border border-slate-200 text-slate-700 text-xs font-bold hover:bg-slate-50 transition"
              >
                Return to Home
              </a>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function ApplicationShell({ children }) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen bg-white text-slate-900 font-sans antialiased">
      {/* Responsive Mobile Header */}
      <header className="flex h-16 items-center justify-between border-b border-blue-100 bg-white px-4 lg:hidden sticky top-0 z-40">
        <button
          type="button"
          onClick={() => setMobileOpen(true)}
          className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-50 text-slate-700 hover:text-blue-600 transition"
          aria-label="Open navigation sidebar"
        >
          <Menu className="h-5 w-5" />
        </button>
        <NavLink to="/" className="relative h-[48px] w-[140px] flex items-center">
          <video
            autoPlay
            muted
            loop
            playsInline
            src="/mailrakhwala-logo.mp4"
            className="h-full w-full object-contain"
            aria-label="MailRakhwala"
          />
        </NavLink>
        <div className="w-10" />
      </header>

      {/* Shared Responsive Mobile Drawer */}
      <MobileSidebarDrawer isOpen={mobileOpen} onClose={() => setMobileOpen(false)} />

      {/* Main Layout */}
      <div className="flex min-h-[calc(100vh-4rem)] lg:min-h-screen">
        <Sidebar />
        <main className="min-w-0 flex-1 overflow-y-auto bg-white">
          <div className="w-full min-h-full">
            <ErrorBoundary>{children}</ErrorBoundary>
          </div>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AnalysisProvider>
      <BrowserRouter>
        <Routes>
          {/* Public / Ingestion */}
          <Route
            path="/"
            element={
              <ApplicationShell>
                <Home />
              </ApplicationShell>
            }
          />

          {/* 1. Dashboard */}
          <Route
            path="/dashboard"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <Dashboard />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />

          {/* 2. Stream Analysis */}
          <Route
            path="/analysis"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <Analysis />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/stream-analysis"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <Analysis />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />

          {/* 3. TLS Analysis */}
          <Route
            path="/tls-analysis"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <TLSAnalysis />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />

          {/* 4. Evidence Explorer */}
          <Route
            path="/evidence"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <EvidenceExplorer />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/evidence-explorer"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <EvidenceExplorer />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />

          {/* 5. Findings & CVEs */}
          <Route
            path="/findings"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <Findings />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />

          {/* 6. Security Posture */}
          <Route
            path="/posture"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <SecurityPosture />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/security-posture"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <SecurityPosture />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />

          {/* 7. Risk Intelligence */}
          <Route
            path="/risk-intelligence"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <RiskIntelligence />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />

          {/* 8. Forensic Reports */}
          <Route
            path="/reports"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <Reports />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/forensic-reports"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <Reports />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />

          {/* Reference / Documentation */}
          <Route
            path="/documentation"
            element={
              <ApplicationShell>
                <Documentation />
              </ApplicationShell>
            }
          />

          {/* Backward-compatible redirects for consolidated destinations */}
          <Route path="/anomaly-detection" element={<Navigate to="/risk-intelligence?tab=anomaly" replace />} />
          <Route path="/threat-context" element={<Navigate to="/risk-intelligence?tab=threats" replace />} />
          <Route path="/explainability" element={<Navigate to="/risk-intelligence?tab=shap" replace />} />
          <Route path="/ml-explainability" element={<Navigate to="/risk-intelligence?tab=shap" replace />} />
          <Route path="/feature-vector" element={<Navigate to="/risk-intelligence?tab=feature-vector" replace />} />
          <Route path="/rules" element={<Navigate to="/posture" replace />} />
          <Route path="/security-rules" element={<Navigate to="/posture" replace />} />
          <Route path="/analytics" element={<Navigate to="/dashboard" replace />} />
          <Route path="/security-analytics" element={<Navigate to="/dashboard" replace />} />
          <Route path="/export-evidence" element={<Navigate to="/reports" replace />} />
          <Route path="/settings" element={<Navigate to="/dashboard" replace />} />
          <Route path="/analysis-settings" element={<Navigate to="/dashboard" replace />} />

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AnalysisProvider>
  );
}
