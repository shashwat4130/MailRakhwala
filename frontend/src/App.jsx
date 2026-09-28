import React, { useEffect, useRef } from 'react';
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  useNavigate,
} from 'react-router-dom';

import Sidebar from './components/Sidebar';

import Home from './pages/Home';
import Dashboard from './pages/Dashboard';
import Analysis from './pages/Analysis';
import Findings from './pages/Findings';
import Reports from './pages/Reports';
import Documentation from './pages/Documentation';

function ApplicationShell({ children }) {
  return (
    <div className="min-h-screen bg-white text-slate-900 font-sans antialiased">
      <div className="flex min-h-screen">
        <Sidebar />
        <main className="min-w-0 flex-1 overflow-y-auto bg-white">
          <div className="w-full min-h-screen">{children}</div>
        </main>
      </div>
    </div>
  );
}

function ReloadToNewCapture() {
  const navigate = useNavigate();
  const checkedRef = useRef(false);

  useEffect(() => {
    if (checkedRef.current) return;
    checkedRef.current = true;

    const navigation = performance.getEntriesByType('navigation')[0];

    if (navigation?.type !== 'reload') return;

    localStorage.removeItem('active_analysis_id');
    localStorage.removeItem('analysis_id');
    window.dispatchEvent(new Event('analysisIdChanged'));

    const currentPath = window.location.pathname;

    if (currentPath !== '/' && currentPath !== '/documentation') {
      navigate('/', { replace: true });
    }
  }, [navigate]);

  return null;
}

export default function App() {
  return (
    <BrowserRouter>
      <ReloadToNewCapture />

      <Routes>
        <Route path="/" element={<Home />} />

        <Route
          path="/dashboard"
          element={
            <ApplicationShell>
              <Dashboard />
            </ApplicationShell>
          }
        />

        <Route
          path="/analysis"
          element={
            <ApplicationShell>
              <Analysis />
            </ApplicationShell>
          }
        />

        <Route
          path="/findings"
          element={
            <ApplicationShell>
              <Findings />
            </ApplicationShell>
          }
        />

        <Route
          path="/reports"
          element={
            <ApplicationShell>
              <Reports />
            </ApplicationShell>
          }
        />

        <Route path="/documentation" element={<Documentation />} />

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
