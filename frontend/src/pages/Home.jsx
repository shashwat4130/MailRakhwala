import React, { useState, useRef } from 'react';
import { uploadCapture } from '../services/api';

export default function Home() {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    const selected = e.target.files?.[0];
    setErrorMessage(null);
    setUploadResult(null);

    if (selected) {
      const lower = selected.name.toLowerCase();
      if (!lower.endsWith('.pcap') && !lower.endsWith('.pcapng')) {
        setErrorMessage('Only .pcap and .pcapng packet capture files are supported.');
        setFile(null);
        return;
      }
      setFile(selected);
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setErrorMessage('Please select a .pcap or .pcapng file first.');
      return;
    }

    setUploading(true);
    setErrorMessage(null);
    setUploadResult(null);

    try {
      const result = await uploadCapture(file);
      setUploadResult(result);
    } catch (err) {
      const detail = err.response?.data?.detail || err.message || 'Capture upload failed.';
      setErrorMessage(detail);
    } finally {
      setUploading(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setUploadResult(null);
    setErrorMessage(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white">Capture File Ingestion</h2>
        <p className="text-sm text-gray-400 mt-1">
          Passive, zero-decryption cryptographic inspection for email communications.
        </p>
      </div>

      <div className="border border-dashed border-gray-800 hover:border-gray-700 bg-gray-950/60 rounded-xl py-8 px-6 text-center transition-colors">
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          accept=".pcap,.pcapng"
          className="hidden"
          id="pcap-file-input"
        />

        <div className="max-w-md mx-auto space-y-4">
          <p className="text-xs text-gray-400">
            Select a <code className="text-gray-300">.pcap</code> or <code className="text-gray-300">.pcapng</code> capture file to queue for analysis.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-3">
            <label
              htmlFor="pcap-file-input"
              className="px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors cursor-pointer inline-flex items-center justify-center shadow-sm"
            >
              {file ? 'Change Capture File' : 'Browse PCAP / PCAPNG'}
            </label>

            <button
              type="button"
              onClick={handleUpload}
              disabled={!file || uploading}
              className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors inline-flex items-center justify-center ${
                !file || uploading
                  ? 'bg-gray-800/80 text-gray-500 border border-gray-800 cursor-not-allowed'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white cursor-pointer shadow-sm'
              }`}
            >
              {uploading ? 'Ingesting & Validating...' : 'Upload & Enqueue'}
            </button>

            {(file || uploadResult || errorMessage) && (
              <button
                type="button"
                onClick={handleReset}
                disabled={uploading}
                className="px-3 py-2 text-sm font-medium rounded-lg bg-gray-900 text-gray-400 hover:text-white border border-gray-800 transition-colors cursor-pointer"
              >
                Reset
              </button>
            )}
          </div>

          {file && (
            <div className="text-xs font-mono text-gray-300 pt-1">
              Selected: <span className="text-blue-400 font-semibold">{file.name}</span> ({(file.size / 1024).toFixed(1)} KB)
            </div>
          )}
        </div>
      </div>

      {errorMessage && (
        <div className="p-4 rounded-lg bg-rose-950/30 border border-rose-800/50 text-rose-300 text-sm">
          <strong className="text-rose-200">Validation Error:</strong> {errorMessage}
        </div>
      )}

      {uploadResult && (
        <div className="p-4 rounded-lg bg-emerald-950/30 border border-emerald-800/50 text-emerald-300 text-sm space-y-1">
          <div className="font-semibold text-emerald-200">Capture Ingested Successfully</div>
          <div className="font-mono text-xs text-emerald-300/90">Filename: <span className="text-white">{uploadResult.filename}</span></div>
          <div className="font-mono text-xs text-emerald-300/90">Analysis ID: <span className="text-emerald-400">{uploadResult.analysis_id}</span></div>
          <div className="font-mono text-xs text-emerald-300/90">Status: <span className="uppercase text-amber-400">{uploadResult.status}</span></div>
          <div className="text-xs text-emerald-400/80 pt-1">{uploadResult.message}</div>
        </div>
      )}
    </div>
  );
}