import React, { useEffect, useState } from 'react';
import { Shield, Radio } from 'lucide-react';
import { checkHealth } from '../services/api';

export default function Navbar() {
  const [healthStatus, setHealthStatus] = useState('CHECKING');

  useEffect(() => {
    let isMounted = true;

    const verifyBackend = async () => {
      try {
        await checkHealth();
        if (isMounted) setHealthStatus('ONLINE');
      } catch (err) {
        if (isMounted) setHealthStatus('OFFLINE');
      }
    };

    verifyBackend();
    const interval = setInterval(verifyBackend, 15000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <header className="h-16 border-b border-gray-800 bg-[#111827]/80 backdrop-blur-sm px-6 flex items-center justify-between sticky top-0 z-50">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-blue-600/10 border border-blue-500/20 text-blue-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-semibold tracking-wide text-white text-base">MailRakhwala</span>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded border border-gray-700 bg-gray-800 text-gray-300">
              SIH26159
            </span>
          </div>
          <p className="text-xs text-gray-400 hidden sm:block">
            AI-Assisted Cryptographic Posture Assessment
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-full border border-gray-800 bg-gray-950">
          <Radio
            className={`w-3.5 h-3.5 ${
              healthStatus === 'ONLINE'
                ? 'text-emerald-400 animate-pulse'
                : healthStatus === 'OFFLINE'
                ? 'text-rose-500'
                : 'text-amber-400'
            }`}
          />
          <span className="text-gray-400">CORE API:</span>
          <span
            className={
              healthStatus === 'ONLINE'
                ? 'text-emerald-400'
                : healthStatus === 'OFFLINE'
                ? 'text-rose-400'
                : 'text-amber-400'
            }
          >
            {healthStatus}
          </span>
        </div>
      </div>
    </header>
  );
}