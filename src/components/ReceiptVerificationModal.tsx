import React, { useState } from 'react';
import {
  X,
  FileCheck,
  Upload,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Hash,
  Clock,
  Layers,
  FileText,
  User,
  Fingerprint,
} from 'lucide-react';
import {
  PrimaryButton,
  SecondaryButton,
  StatusBadge,
  VerificationBadge,
  KeyValueRow,
  TechnicalDetails,
} from './ui/designSystem';
import { ReceiptService } from '../services/receiptService';
import { ReceiptVerificationResult, SignedOfflineReceipt } from '../types';

interface ReceiptVerificationModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ReceiptVerificationModal: React.FC<ReceiptVerificationModalProps> = ({
  isOpen,
  onClose,
}) => {
  const [inputText, setInputText] = useState<string>('');
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [result, setResult] = useState<ReceiptVerificationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setSelectedFileName(file.name);
    setError(null);

    const reader = new FileReader();
    reader.onload = async (event) => {
      const content = event.target?.result;
      if (typeof content === 'string') {
        setInputText(content);
        await runVerification(content);
      }
    };
    reader.onerror = () => {
      setError('Failed to read the selected receipt file.');
    };
    reader.readAsText(file);
  };

  const runVerification = async (contentToVerify: string) => {
    if (!contentToVerify.trim()) {
      setError('Please provide receipt content or select a .sihrcpt file.');
      return;
    }

    setIsVerifying(true);
    setError(null);
    try {
      const res = await ReceiptService.verifyReceipt(contentToVerify);
      setResult(res);
    } catch (err: any) {
      console.error('Receipt verification failed:', err);
      setError(err.message || 'Verification process encountered an unexpected error.');
      setResult(null);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleReset = () => {
    setInputText('');
    setSelectedFileName(null);
    setResult(null);
    setError(null);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/50 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6 animate-in fade-in duration-150">
      <div className="w-full max-w-2xl bg-white rounded-2xl shadow-2xl border border-slate-200 overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200/90 flex items-center justify-between bg-slate-50/70">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-indigo-50 border border-indigo-100 rounded-lg text-indigo-700">
              <FileCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">
                Verify Offline Receipt (.sihrcpt)
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                NIST FIPS 204 (ML-DSA-65) cryptographic signature &amp; ledger provenance verification
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {!result ? (
            <div className="space-y-4">
              {/* File Dropzone */}
              <label className="border-2 border-dashed border-slate-200 hover:border-indigo-400 rounded-xl p-6 flex flex-col items-center justify-center text-center cursor-pointer bg-slate-50/50 hover:bg-indigo-50/20 transition-all">
                <Upload className="w-8 h-8 text-indigo-600 mb-2" />
                <span className="text-xs font-semibold text-slate-800">
                  {selectedFileName ? selectedFileName : 'Choose .sihrcpt receipt file'}
                </span>
                <span className="text-[11px] text-slate-500 mt-0.5">
                  Drag and drop or browse from local filesystem
                </span>
                <input
                  type="file"
                  accept=".sihrcpt,.json"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>

              {/* Paste JSON Textarea */}
              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-slate-700">
                  Or paste raw receipt JSON:
                </label>
                <textarea
                  value={inputText}
                  onChange={(e) => {
                    setInputText(e.target.value);
                    setError(null);
                  }}
                  rows={6}
                  placeholder={`{\n  "magic": "SIHRCPT01",\n  "version": 1,\n  "receiptId": "RCPT-...",\n  "signatureAlgorithm": "ML-DSA-65",\n  ...\n}`}
                  className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs font-mono text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                />
              </div>

              {error && (
                <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-700 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <div className="flex justify-end pt-2">
                <PrimaryButton
                  icon={<FileCheck className="w-4 h-4" />}
                  loading={isVerifying}
                  disabled={!inputText.trim()}
                  onClick={() => runVerification(inputText)}
                >
                  Verify Receipt Authenticity
                </PrimaryButton>
              </div>
            </div>
          ) : (
            /* Verification Results */
            <div className="space-y-5 animate-in fade-in duration-200">
              {/* Verdict Banner */}
              <div
                className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                  result.provenanceAssurance === 'AUTHENTIC_AND_LEDGER_CONFIRMED'
                    ? 'bg-emerald-50/80 border-emerald-200 text-emerald-950'
                    : result.provenanceAssurance === 'SIGNATURE_VALID_UNCONFIRMED_LEDGER'
                    ? 'bg-amber-50/80 border-amber-200 text-amber-950'
                    : 'bg-rose-50/80 border-rose-200 text-rose-950'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 ${
                      result.provenanceAssurance === 'AUTHENTIC_AND_LEDGER_CONFIRMED'
                        ? 'bg-emerald-600 text-white'
                        : result.provenanceAssurance === 'SIGNATURE_VALID_UNCONFIRMED_LEDGER'
                        ? 'bg-amber-600 text-white'
                        : 'bg-rose-600 text-white'
                    }`}
                  >
                    {result.valid ? (
                      <CheckCircle2 className="w-6 h-6" />
                    ) : (
                      <AlertTriangle className="w-6 h-6" />
                    )}
                  </div>
                  <div>
                    <h3 className="text-sm font-bold">
                      {result.provenanceAssurance === 'AUTHENTIC_AND_LEDGER_CONFIRMED' && 'OFFLINE RECEIPT AUTHENTIC & LEDGER CORROBORATED'}
                      {result.provenanceAssurance === 'SIGNATURE_VALID_UNCONFIRMED_LEDGER' && 'VALID SIGNATURE · UNCONFIRMED IN LOCAL LEDGER'}
                      {result.provenanceAssurance === 'UNTRUSTED_OR_TAMPERED' && 'VERIFICATION FAILED: UNTRUSTED OR TAMPERED'}
                      {result.provenanceAssurance === 'INVALID_STRUCTURE' && 'INVALID RECEIPT CONTAINER STRUCTURE'}
                    </h3>
                    <p className="text-xs mt-0.5 opacity-90 leading-relaxed">
                      {result.assuranceSummary}
                    </p>
                  </div>
                </div>

                <div className="shrink-0 flex items-center gap-1.5 flex-wrap">
                  <StatusBadge status={result.signatureValid ? 'verified' : 'failed'}>
                    {result.signatureValid ? 'ML-DSA-65 Valid' : 'Bad Signature'}
                  </StatusBadge>
                  <StatusBadge status={result.identityBound ? 'verified' : 'failed'}>
                    {result.identityBound ? 'Identity Bound' : 'Untrusted Key'}
                  </StatusBadge>
                  <StatusBadge status={result.ledgerVerified ? 'verified' : 'pending'}>
                    {result.ledgerVerified ? 'Ledger Ratified' : 'Ledger Unconfirmed'}
                  </StatusBadge>
                </div>
              </div>

              {/* Errors & Warnings */}
              {result.errors.length > 0 && (
                <div className="p-3.5 bg-rose-50/80 border border-rose-200 rounded-xl space-y-1 text-xs text-rose-800">
                  <strong className="block font-semibold">Verification Failures:</strong>
                  <ul className="list-disc pl-4 space-y-0.5">
                    {result.errors.map((err, idx) => (
                      <li key={idx}>{err}</li>
                    ))}
                  </ul>
                </div>
              )}

              {result.warnings.length > 0 && (
                <div className="p-3 bg-amber-50/80 border border-amber-200 rounded-xl space-y-1 text-xs text-amber-800">
                  <strong className="block font-semibold">Provenance Notices:</strong>
                  <ul className="list-disc pl-4 space-y-0.5">
                    {result.warnings.map((warn, idx) => (
                      <li key={idx}>{warn}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Provenance Metadata Grid */}
              {result.receipt && (
                <div className="bg-slate-50/70 border border-slate-200/80 rounded-xl p-4 space-y-3">
                  <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                    Receipt Provenance Metadata
                  </h4>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    <div className="p-2.5 bg-white rounded-lg border border-slate-200/60 space-y-0.5">
                      <span className="text-[10px] text-slate-500 font-medium">Receipt ID</span>
                      <div className="font-mono font-semibold text-slate-900">{result.receipt.receiptId}</div>
                    </div>

                    <div className="p-2.5 bg-white rounded-lg border border-slate-200/60 space-y-0.5">
                      <span className="text-[10px] text-slate-500 font-medium">Recipient Signer</span>
                      <div className="font-semibold text-slate-900">
                        {result.receipt.recipientName} ({result.receipt.recipientId})
                      </div>
                    </div>

                    <div className="p-2.5 bg-white rounded-lg border border-slate-200/60 space-y-0.5">
                      <span className="text-[10px] text-slate-500 font-medium">Document Title</span>
                      <div className="font-semibold text-slate-900">{result.receipt.documentTitle}</div>
                    </div>

                    <div className="p-2.5 bg-white rounded-lg border border-slate-200/60 space-y-0.5">
                      <span className="text-[10px] text-slate-500 font-medium">Classification</span>
                      <div className="font-semibold text-indigo-700">{result.receipt.classification}</div>
                    </div>

                    <div className="p-2.5 bg-white rounded-lg border border-slate-200/60 space-y-0.5">
                      <span className="text-[10px] text-slate-500 font-medium">Decryption Timestamp</span>
                      <div className="text-slate-900 font-medium">
                        {new Date(result.receipt.decryptionTimestamp).toLocaleString()}
                      </div>
                    </div>

                    <div className="p-2.5 bg-white rounded-lg border border-slate-200/60 space-y-0.5">
                      <span className="text-[10px] text-slate-500 font-medium">Ledger Commitment</span>
                      <div className="text-slate-900 font-mono">
                        Block #{result.receipt.blockHeight}
                      </div>
                    </div>
                  </div>

                  <TechnicalDetails title="Cryptographic Signature &amp; Watermark Diagnostics">
                    <KeyValueRow label="Signature Algorithm" value={result.receipt.signatureAlgorithm} />
                    <KeyValueRow label="Watermark ID" value={result.receipt.watermarkId} copyable />
                    <KeyValueRow label="Watermark Commitment" value={result.receipt.watermarkCommitment} copyable />
                    <KeyValueRow label="Decryption Event ID" value={result.receipt.decryptionEventId} copyable />
                    <KeyValueRow label="Block Hash" value={result.receipt.blockHash} copyable />
                    <KeyValueRow label="Recipient Key Fingerprint" value={result.receipt.recipientFingerprint} copyable />
                    <KeyValueRow label="Signature (Base64)" value={result.receipt.signatureBase64.slice(0, 64) + '...'} copyable />
                  </TechnicalDetails>
                </div>
              )}

              {/* Action buttons */}
              <div className="flex items-center justify-between pt-2">
                <SecondaryButton onClick={handleReset}>
                  Verify another receipt
                </SecondaryButton>
                <PrimaryButton onClick={onClose}>
                  Done
                </PrimaryButton>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
