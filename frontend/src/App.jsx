import React, { useState, useEffect } from 'react';
import {
  BrowserRouter,
  Routes,
  Route,
  NavLink,
  useLocation,
  useNavigate,
  Navigate,
} from 'react-router-dom';
import { Menu, BookOpen, UploadCloud, RefreshCw } from 'lucide-react';

import { AnalysisProvider, useAnalysisContext } from './context/AnalysisContext';
import Sidebar, { MobileSidebarDrawer } from './components/Sidebar';
import MailRakhwalaLogo from './components/MailRakhwalaLogo';
import CaptureModal from './components/CaptureModal';

import { motion } from 'framer-motion';

// Synchronously clear active session and reset browser history to '/' strictly on initial document load or full browser reload
// (runs only once on script execution; never during in-app client-side navigation)
if (typeof window !== 'undefined') {
  try {
    localStorage.removeItem('active_analysis_id');
    localStorage.removeItem('analysis_id');
    sessionStorage.clear();
    if (window.location.pathname !== '/') {
      window.history.replaceState(null, '', '/');
    }
  } catch (_) {}
}

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

// Route Aliases
import SecurityAnalytics from './pages/SecurityAnalytics';
import SecurityRules from './pages/SecurityRules';
import AnomalyDetection from './pages/AnomalyDetection';
import ThreatContext from './pages/ThreatContext';
import MLExplainability from './pages/MLExplainability';
import AnalysisSettings from './pages/AnalysisSettings';
import ExportEvidence from './pages/ExportEvidence';

/**
 * RequireAnalysisSession
 * 
 * Allows direct URL navigation and refresh while allowing every analysis page
 * to gracefully render its customized EmptyAnalysisState when no PCAP is active.
 */
function RequireAnalysisSession({ children }) {
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
        <div className="flex min-h-[70vh] items-center justify-center p-8 bg-[#F7F7F5]">
          <div className="max-w-md w-full rounded-2xl border border-[#E5E5E0] bg-white p-8 text-center shadow-sm">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-[#111111] text-white mb-4">
              <RefreshCw className="w-5 h-5" />
            </div>
            <h2 className="text-xl font-bold text-[#111111] mb-2">
              Console Rendering Discrepancy
            </h2>
            <p className="text-xs text-[#666666] mb-6 leading-relaxed">
              {this.state.error?.message || 'An unexpected rendering error occurred in this view.'}
            </p>
            <div className="flex items-center justify-center gap-3">
              <button
                type="button"
                onClick={() => this.setState({ hasError: false, error: null })}
                className="px-4 py-2 rounded-lg bg-[#111111] text-white text-xs font-bold uppercase tracking-wider shadow hover:bg-[#222222] transition"
              >
                Retry View
              </button>
              <a
                href="/"
                className="px-4 py-2 rounded-lg border border-[#E5E5E0] bg-white text-xs font-bold text-[#111111] hover:bg-[#F7F7F5] transition"
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
  const location = useLocation();

  return (
    <div className="min-h-screen bg-[#F7F7F5] text-[#111111] font-sans antialiased flex flex-row">
      {/* Global Capture Modal (Triggered via Sidebar or anywhere) */}
      <CaptureModal />

      {/* Shared Responsive Mobile Drawer */}
      <MobileSidebarDrawer isOpen={mobileOpen} onClose={() => setMobileOpen(false)} />

      {/* Desktop Sticky Sidebar - Full Viewport 100vh, always accessible */}
      <Sidebar />

      {/* Minimal Floating Mobile Trigger on small viewports */}
      <button
        type="button"
        onClick={() => setMobileOpen(true)}
        className="fixed top-3.5 left-3.5 z-40 lg:hidden flex h-9 w-9 items-center justify-center rounded-xl bg-[#111111] text-white shadow-md hover:bg-[#222222] transition active:scale-95"
        aria-label="Open navigation menu"
      >
        <Menu className="h-4.5 w-4.5" />
      </button>

      {/* Main Application Area */}
      <div className="flex-1 flex flex-col min-w-0 min-h-screen">
        {/* Page Content with Subtle Route Transition */}
        <main className="flex-1 min-w-0 bg-[#F7F7F5]">
          <ErrorBoundary>
            <motion.div
              key={location.pathname}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.18, ease: 'easeOut' }}
              className="min-h-full"
            >
              {children}
            </motion.div>
          </ErrorBoundary>
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
            path="/streams"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <Analysis />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
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
            path="/tls"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <TLSAnalysis />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
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

          {/* Reference: Documentation */}
          <Route
            path="/documentation"
            element={
              <ApplicationShell>
                <Documentation />
              </ApplicationShell>
            }
          />

          {/* Aliases & Internal Intelligence Views */}
          <Route
            path="/analytics"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <SecurityAnalytics />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/security-analytics"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <SecurityAnalytics />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/rules"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <SecurityRules />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/security-rules"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <SecurityRules />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/anomaly-detection"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <AnomalyDetection />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/threat-context"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <ThreatContext />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/explainability"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <MLExplainability />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/ml-explainability"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <MLExplainability />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/settings"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <AnalysisSettings />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/analysis-settings"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <AnalysisSettings />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />
          <Route
            path="/export-evidence"
            element={
              <RequireAnalysisSession>
                <ApplicationShell>
                  <ExportEvidence />
                </ApplicationShell>
              </RequireAnalysisSession>
            }
          />

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AnalysisProvider>
  );
}
