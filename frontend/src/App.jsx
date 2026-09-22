import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

import Sidebar from './components/Sidebar';

import Home from './pages/Home';
import Dashboard from './pages/Dashboard';
import Analysis from './pages/Analysis';
import Findings from './pages/Findings';
import Reports from './pages/Reports';

function ApplicationShell({ children }) {
  return (
    <div className="min-h-screen bg-white text-slate-900 font-sans antialiased">
      <div className="flex min-h-screen">
        <Sidebar />

        <main className="min-w-0 flex-1 overflow-y-auto bg-white">
          <div className="w-full min-h-screen">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>

        {/* Home / PCAP Upload */}
        <Route
          path="/"
          element={<Home />}
        />

        {/* Dashboard */}
        <Route
          path="/dashboard"
          element={
            <ApplicationShell>
              <Dashboard />
            </ApplicationShell>
          }
        />

        {/* Analysis */}
        <Route
          path="/analysis"
          element={
            <ApplicationShell>
              <Analysis />
            </ApplicationShell>
          }
        />

        {/* Findings */}
        <Route
          path="/findings"
          element={
            <ApplicationShell>
              <Findings />
            </ApplicationShell>
          }
        />

        {/* Reports */}
        <Route
          path="/reports"
          element={
            <ApplicationShell>
              <Reports />
            </ApplicationShell>
          }
        />

      </Routes>
    </BrowserRouter>
  );
}