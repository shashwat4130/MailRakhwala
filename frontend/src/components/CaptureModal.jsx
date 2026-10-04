import React, { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAnalysisContext } from '../context/AnalysisContext';
import CaptureConsole from './CaptureConsole';

export default function CaptureModal() {
  const { isCaptureModalOpen, closeCaptureModal } = useAnalysisContext();

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isCaptureModalOpen) {
        closeCaptureModal();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isCaptureModalOpen, closeCaptureModal]);

  return (
    <AnimatePresence>
      {isCaptureModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 overflow-y-auto">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={closeCaptureModal}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm"
            aria-hidden="true"
          />

          <motion.div
            initial={{ opacity: 0, scale: 0.97, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: 10 }}
            transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
            className="relative z-10 w-full max-w-2xl my-auto"
          >
            <CaptureConsole isModal={true} onClose={closeCaptureModal} />
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
