import React, { useState } from 'react';
import {
  Upload,
  ShieldCheck,
  ShieldAlert,
  FileCode,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Search,
  ExternalLink,
  Clipboard,
  FileText,
} from 'lucide-react';
import { ForensicAttributionCertificate, CertificateVerificationResult } from '../types';
import { ForensicCertificateService } from '../services/forensicCertificateService';
import { WorkstationSurface, OperationalButton } from './ui/WorkstationPrimitives';
import { ForensicAttributionCertificateViewer } from './ForensicAttributionCertificateViewer';

interface CertificateVerificationSectionProps {
  onNavigateToLedger?: () => void;
}

export const CertificateVerificationSection: React.FC<CertificateVerificationSectionProps> = ({
  onNavigateToLedger,
}) => {
  const [jsonInput, setJsonInput] = useState<string>('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [loadedCertificate, setLoadedCertificate] = useState<ForensicAttributionCertificate | null>(null);
  const [verificationResult, setVerificationResult] = useState<CertificateVerificationResult | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const processCertificateJson = async (rawJson: string) => {
    setErrorMsg(null);
    setVerificationResult(null);
    setLoadedCertificate(null);

    try {
      const parsed = JSON.parse(rawJson) as ForensicAttributionCertificate;
      setLoadedCertificate(parsed);

      setIsVerifying(true);
      await new Promise((r) => setTimeout(r, 450));
      const res = await ForensicCertificateService.verifyCertificate(parsed);
      setVerificationResult(res);
    } catch (err: any) {
      setErrorMsg(`Failed to parse certificate: ${err.message || 'Invalid JSON format'}`);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleFileUpload = (file: File) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setJsonInput(content);
      processCertificateJson(content);
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      handleFileUpload(file);
    }
  };

  return (
    <div className="space-y-6">
      <WorkstationSurface variant="primary" className="p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200">
          <div>
            <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wide flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              Independent Certificate Authenticity Verification
            </h3>
            <p className="text-xs text-slate-500 font-sans">
              Verify any exported Forensic Attribution Certificate (.cert.json) against local Post-Quantum keys and immutable DLT state.
            </p>
          </div>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 self-start sm:self-auto">
            RFC 8785 CANONICAL AUDIT
          </span>
        </div>

        {/* Drag and Drop Zone */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-xl p-6 text-center transition-all ${
            dragOver
              ? 'border-indigo-500 bg-indigo-50/50'
              : 'border-slate-300 bg-slate-50/50 hover:bg-slate-50'
          }`}
        >
          <div className="space-y-2">
            <div className="mx-auto w-10 h-10 rounded-full bg-slate-100 flex items-center justify-center text-slate-500">
              <Upload className="w-5 h-5 text-indigo-600" />
            </div>
            <div>
              <label
                htmlFor="cert-file-input"
                className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 cursor-pointer"
              >
                Choose a .cert.json file
              </label>
              <span className="text-xs text-slate-500"> or drag and drop it here</span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              Accepts .cert.json or standard forensic attribution JSON exports
            </p>
            <input
              id="cert-file-input"
              type="file"
              accept=".json,.cert.json"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFileUpload(f);
              }}
            />
          </div>
        </div>

        {/* Or Paste Raw JSON */}
        <div className="space-y-2">
          <label className="text-xs font-semibold text-slate-700 flex items-center justify-between">
            <span>Or paste certificate JSON payload:</span>
            {jsonInput && (
              <button
                type="button"
                onClick={() => {
                  setJsonInput('');
                  setLoadedCertificate(null);
                  setVerificationResult(null);
                  setErrorMsg(null);
                }}
                className="text-[11px] text-slate-500 hover:text-slate-800 cursor-pointer font-normal"
              >
                Clear input
              </button>
            )}
          </label>
          <textarea
            rows={4}
            value={jsonInput}
            onChange={(e) => setJsonInput(e.target.value)}
            placeholder='Paste {"certificateId": "CERT-2026-...", "caseId": "CASE-2026-...", ...} here'
            className="w-full text-xs font-mono p-3 rounded-lg border border-slate-300 bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500"
          />
        </div>

        <div className="flex justify-end gap-2">
          <OperationalButton
            variant="operational"
            size="sm"
            onClick={() => processCertificateJson(jsonInput)}
            disabled={!jsonInput.trim() || isVerifying}
            icon={isVerifying ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
          >
            {isVerifying ? 'Auditing Certificate...' : 'Verify Certificate Now'}
          </OperationalButton>
        </div>

        {errorMsg && (
          <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}
      </WorkstationSurface>

      {/* Verification Results Matrix */}
      {verificationResult && (
        <WorkstationSurface variant="primary" className="p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-200">
            <div className="flex items-center gap-2">
              {verificationResult.valid ? (
                <div className="w-6 h-6 rounded-full bg-emerald-100 flex items-center justify-center text-emerald-700">
                  <CheckCircle2 className="w-4 h-4" />
                </div>
              ) : (
                <div className="w-6 h-6 rounded-full bg-rose-100 flex items-center justify-center text-rose-700">
                  <XCircle className="w-4 h-4" />
                </div>
              )}
              <div>
                <h4 className="text-sm font-bold text-slate-900">
                  {verificationResult.valid
                    ? 'CERTIFICATE AUTHENTICATED & CRYPTOGRAPHICALLY SOUND'
                    : 'CERTIFICATE VERIFICATION FAILED / TAMPER DETECTED'}
                </h4>
                <p className="text-xs text-slate-500 font-mono">
                  {verificationResult.valid
                    ? 'All cryptographic non-repudiation assertions and ledger anchors confirmed.'
                    : `Tamper Alert: ${verificationResult.tamperReason}`}
                </p>
              </div>
            </div>

            <span
              className={`text-xs font-mono font-bold px-2.5 py-1 rounded border ${
                verificationResult.valid
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-300'
                  : 'bg-rose-50 text-rose-800 border-rose-300'
              }`}
            >
              {verificationResult.valid ? 'VERIFIED' : 'TAMPERED / INVALID'}
            </span>
          </div>

          {/* Verification Detailed Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            {verificationResult.details.map((check, idx) => (
              <div
                key={idx}
                className={`p-3 rounded-lg border flex items-start gap-2.5 ${
                  check.passed
                    ? 'bg-slate-50 border-slate-200 text-slate-800'
                    : 'bg-rose-50 border-rose-200 text-rose-800'
                }`}
              >
                {check.passed ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                )}
                <div className="space-y-0.5 min-w-0">
                  <span className="font-semibold block font-sans">{check.check}</span>
                  <span className="text-[11px] text-slate-500 block truncate">{check.message}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Certificate Viewer for the verified certificate */}
          {loadedCertificate && verificationResult.valid && (
            <div className="pt-4 border-t border-slate-200">
              <span className="text-xs font-bold text-slate-800 uppercase tracking-wide block mb-3 font-sans">
                Verified Certificate Visual Representation
              </span>
              <ForensicAttributionCertificateViewer
                certificate={loadedCertificate}
                onNavigateToLedger={onNavigateToLedger}
              />
            </div>
          )}
        </WorkstationSurface>
      )}
    </div>
  );
};
