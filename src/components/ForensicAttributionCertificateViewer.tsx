import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Download,
  FileText,
  FileCode,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Award,
  Layers,
  Fingerprint,
  Database,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  AlertTriangle,
  Scale,
} from 'lucide-react';
import { ForensicAttributionCertificate, CertificateVerificationResult } from '../types';
import { ForensicCertificateService } from '../services/forensicCertificateService';
import { WorkstationSurface, OperationalButton, StatusBadge } from './ui/WorkstationPrimitives';

interface ForensicAttributionCertificateViewerProps {
  certificate: ForensicAttributionCertificate;
  onNavigateToLedger?: () => void;
  className?: string;
}

export const ForensicAttributionCertificateViewer: React.FC<ForensicAttributionCertificateViewerProps> = ({
  certificate,
  onNavigateToLedger,
  className = '',
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<CertificateVerificationResult | null>(null);
  const [showVerificationDrawer, setShowVerificationDrawer] = useState(false);
  const [showFullSignature, setShowFullSignature] = useState(false);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDownloadPdf = async () => {
    try {
      setIsDownloadingPdf(true);
      await ForensicCertificateService.downloadCertificatePdf(certificate);
    } catch (err) {
      console.error('Failed to generate PDF certificate:', err);
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const handleDownloadJson = () => {
    ForensicCertificateService.downloadCertificateJson(certificate);
  };

  const handleVerifyNow = async () => {
    setIsVerifying(true);
    setShowVerificationDrawer(true);
    try {
      await new Promise((r) => setTimeout(r, 400));
      const result = await ForensicCertificateService.verifyCertificate(certificate);
      setVerificationResult(result);
    } catch (err) {
      console.error('Verification error:', err);
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Official Certificate Card */}
      <div className="relative overflow-hidden rounded-2xl border-2 border-slate-300 bg-white shadow-xl">
        {/* Certificate Watermark Seal Accent */}
        <div className="absolute -top-12 -right-12 w-48 h-48 rounded-full bg-emerald-500/5 pointer-events-none blur-2xl" />
        <div className="absolute top-0 left-0 right-0 h-2 bg-gradient-to-r from-slate-900 via-indigo-900 to-emerald-700" />

        {/* Certificate Header Banner */}
        <div className="p-5 sm:p-6 border-b border-slate-200 bg-slate-50/80">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="p-1.5 rounded-lg bg-emerald-100 text-emerald-800">
                  <Award className="w-5 h-5 text-emerald-700" />
                </span>
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight flex items-center gap-2">
                    FORENSIC ATTRIBUTION CERTIFICATE
                    <span className="text-[10px] font-mono font-bold text-emerald-800 bg-emerald-100 px-2 py-0.5 rounded border border-emerald-300">
                      NIST FIPS 204
                    </span>
                  </h3>
                  <p className="text-xs text-slate-500 font-mono">
                    Official Cryptographic Provenance &amp; Forensic Non-Repudiation Record
                  </p>
                </div>
              </div>
            </div>

            <div className="text-right flex flex-wrap sm:flex-col items-end gap-1 font-mono text-xs">
              <span className="px-2.5 py-1 rounded-md bg-white border border-slate-200 text-slate-800 font-bold shadow-xs">
                {certificate.certificateId}
              </span>
              <span className="text-[11px] text-slate-500">
                CASE: {certificate.caseId}
              </span>
            </div>
          </div>
        </div>

        {/* Certificate Content Body */}
        <div className="p-5 sm:p-6 space-y-6">
          {/* SECTION 1: Technical Attribution Conclusion */}
          <div className="p-4 rounded-xl bg-slate-900 text-white space-y-3 shadow-sm border border-slate-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-emerald-400 uppercase tracking-wider">
                <Scale className="w-4 h-4 text-emerald-400" />
                Technical Forensic Attribution Statement
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700">
                100% MATHEMATICALLY VERIFIED
              </span>
            </div>

            <blockquote className="text-sm font-medium text-slate-100 leading-relaxed border-l-2 border-emerald-500 pl-3 italic">
              &ldquo;{certificate.attributionStatement}&rdquo;
            </blockquote>

            <p className="text-[11px] text-slate-400 leading-normal pt-1 border-t border-slate-800">
              <strong className="text-slate-300">Evidentiary Scope: </strong>
              {certificate.disclaimer}
            </p>
          </div>

          {/* SECTION 2 & 3: Structured Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            {/* Recipient Record */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
              <div className="flex items-center justify-between pb-1.5 border-b border-slate-200">
                <span className="text-[11px] font-bold text-slate-700 uppercase flex items-center gap-1.5 font-sans">
                  <Fingerprint className="w-4 h-4 text-indigo-600" />
                  Attributed Recipient
                </span>
                <span className="text-[10px] text-slate-500">IDENTITY REGISTRY</span>
              </div>

              <div className="space-y-1 font-sans">
                <div className="text-sm font-bold text-slate-900">
                  {certificate.attributionTarget.name}
                </div>
                <div className="text-xs text-slate-600">
                  {certificate.attributionTarget.role} &bull; {certificate.attributionTarget.organization}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-200/70 space-y-1 text-[11px] font-mono text-slate-600">
                <div className="flex justify-between">
                  <span className="text-slate-400">RECIPIENT ID:</span>
                  <span className="font-semibold text-slate-800">{certificate.attributionTarget.recipientId}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">SECURITY CLEARANCE:</span>
                  <span className="font-bold text-indigo-700">{certificate.attributionTarget.clearanceLevel}</span>
                </div>
                <div className="flex justify-between items-center gap-2">
                  <span className="text-slate-400">KEY FINGERPRINT:</span>
                  <span className="font-semibold text-slate-800 truncate max-w-[160px]">
                    {certificate.attributionTarget.publicKeyFingerprint}
                  </span>
                </div>
              </div>
            </div>

            {/* Document & Decryption Event Record */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
              <div className="flex items-center justify-between pb-1.5 border-b border-slate-200">
                <span className="text-[11px] font-bold text-slate-700 uppercase flex items-center gap-1.5 font-sans">
                  <FileText className="w-4 h-4 text-emerald-600" />
                  Target Document &amp; Decryption Event
                </span>
                <span className="text-[10px] text-slate-500">EVENT ANCHOR</span>
              </div>

              <div className="space-y-1 font-sans">
                <div className="text-sm font-bold text-slate-900 truncate">
                  {certificate.document.title}
                </div>
                <div className="text-xs text-slate-600">
                  ID: {certificate.document.documentId} &bull; {certificate.document.classification || 'TOP SECRET'}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-200/70 space-y-1 text-[11px] font-mono text-slate-600">
                <div className="flex justify-between">
                  <span className="text-slate-400">EVENT ID:</span>
                  <span className="font-semibold text-slate-800">{certificate.decryptionSession.eventId}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">SESSION ID:</span>
                  <span className="font-semibold text-slate-800">{certificate.decryptionSession.sessionId}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">DECRYPTED AT:</span>
                  <span className="text-slate-700">{new Date(certificate.decryptionSession.timestampEpochMs).toLocaleString()}</span>
                </div>
              </div>
            </div>
          </div>

          {/* SECTION 4: Cryptographic Non-Repudiation Proof */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-slate-200">
              <span className="font-bold text-slate-800 uppercase flex items-center gap-1.5 font-sans">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                Post-Quantum Cryptographic Proof &amp; DLT Consensus
              </span>
              <button
                type="button"
                onClick={() => setShowFullSignature(!showFullSignature)}
                className="text-indigo-600 hover:text-indigo-800 text-[11px] flex items-center gap-1 cursor-pointer font-sans"
              >
                {showFullSignature ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                {showFullSignature ? 'Hide raw signature' : 'Inspect signature'}
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
              <div className="p-2.5 rounded-lg bg-white border border-slate-200">
                <span className="text-slate-400 block text-[10px] font-sans font-semibold">SIGNATURE ALGORITHM</span>
                <span className="font-bold text-emerald-700">ML-DSA-65 (NIST FIPS 204)</span>
              </div>
              <div className="p-2.5 rounded-lg bg-white border border-slate-200">
                <span className="text-slate-400 block text-[10px] font-sans font-semibold">LEDGER PROVENANCE</span>
                <span className="font-bold text-indigo-700">
                  Block #{certificate.cryptographicProof.ledgerBlockHeight}
                </span>
              </div>
              <div className="p-2.5 rounded-lg bg-white border border-slate-200">
                <span className="text-slate-400 block text-[10px] font-sans font-semibold">BYZANTINE QUORUM</span>
                <span className="font-bold text-emerald-700">
                  RATIFIED ({certificate.cryptographicProof.validatorQuorum.actual} of {certificate.cryptographicProof.validatorQuorum.required})
                </span>
              </div>
            </div>

            {showFullSignature && (
              <div className="p-3 bg-white rounded-lg border border-slate-200 text-[10px] text-slate-700 break-all leading-relaxed space-y-1.5">
                <div className="flex justify-between text-slate-500 font-semibold font-sans">
                  <span>ML-DSA-65 RECIPIENT SIGNATURE (BASE64):</span>
                  <button
                    type="button"
                    onClick={() => handleCopy(certificate.cryptographicProof.recipientSignatureBase64, 'full-sig')}
                    className="text-slate-600 hover:text-slate-900 flex items-center gap-1 cursor-pointer"
                  >
                    {copiedKey === 'full-sig' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    {copiedKey === 'full-sig' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <div>{certificate.cryptographicProof.recipientSignatureBase64}</div>
              </div>
            )}
          </div>

          {/* SECTION 5: Certificate Authenticity Hash (SHA-256) */}
          <div className="p-3 bg-slate-100 rounded-xl border border-slate-200 text-xs font-mono space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider font-sans">
                CANONICAL CERTIFICATE INTEGRITY HASH (SHA-256)
              </span>
              <button
                type="button"
                onClick={() => handleCopy(certificate.certificateHashSha256, 'cert-hash')}
                className="text-slate-600 hover:text-slate-900 flex items-center gap-1 text-[11px] cursor-pointer font-sans"
              >
                {copiedKey === 'cert-hash' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
                {copiedKey === 'cert-hash' ? 'Copied' : 'Copy digest'}
              </button>
            </div>
            <div className="text-[11px] font-semibold text-slate-900 break-all">
              {certificate.certificateHashSha256}
            </div>
          </div>

          {/* Verification Results Panel (if invoked) */}
          {showVerificationDrawer && (
            <div className="p-4 rounded-xl border border-slate-200 bg-white space-y-3 animate-in fade-in">
              <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                <span className="text-xs font-bold text-slate-900 uppercase tracking-wide flex items-center gap-1.5 font-sans">
                  <ShieldCheck className="w-4 h-4 text-emerald-600" />
                  Independent Cryptographic Verification Audit
                </span>
                <span className="text-[11px] font-mono text-slate-500">
                  {isVerifying ? 'Running checks...' : verificationResult?.valid ? '100% VALID' : 'AUDIT FAILED'}
                </span>
              </div>

              {isVerifying ? (
                <div className="p-6 text-center space-y-2 text-slate-500 font-mono text-xs">
                  <RefreshCw className="w-5 h-5 animate-spin mx-auto text-indigo-600" />
                  <div>Verifying canonical certificate hash, ML-DSA-65 signature, and ledger quorum...</div>
                </div>
              ) : verificationResult ? (
                <div className="space-y-2">
                  <div
                    className={`p-3 rounded-lg border text-xs flex items-center justify-between ${
                      verificationResult.valid
                        ? 'bg-emerald-50 text-emerald-900 border-emerald-200'
                        : 'bg-rose-50 text-rose-900 border-rose-200'
                    }`}
                  >
                    <div className="flex items-center gap-2 font-semibold">
                      {verificationResult.valid ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                      ) : (
                        <XCircle className="w-4 h-4 text-rose-600" />
                      )}
                      <span>
                        {verificationResult.valid
                          ? 'Certificate Authenticity & Cryptographic Non-Repudiation Confirmed'
                          : `Certificate Tampering Detected: ${verificationResult.tamperReason}`}
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                    {verificationResult.details.map((d, i) => (
                      <div
                        key={i}
                        className={`p-2.5 rounded-lg border flex items-start gap-2 ${
                          d.passed ? 'bg-slate-50 border-slate-200 text-slate-800' : 'bg-rose-50 border-rose-200 text-rose-800'
                        }`}
                      >
                        {d.passed ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0 mt-0.5" />
                        ) : (
                          <AlertTriangle className="w-3.5 h-3.5 text-rose-600 shrink-0 mt-0.5" />
                        )}
                        <div className="space-y-0.5">
                          <span className="font-semibold block">{d.check}</span>
                          <span className="text-[11px] text-slate-500 block">{d.message}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          )}

          {/* Action Bar */}
          <div className="pt-3 border-t border-slate-200 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <OperationalButton
                variant="operational"
                size="sm"
                onClick={handleDownloadPdf}
                disabled={isDownloadingPdf}
                icon={<Download className="w-3.5 h-3.5 text-white" />}
              >
                {isDownloadingPdf ? 'Generating PDF...' : 'Download Court-Ready PDF (.pdf)'}
              </OperationalButton>

              <OperationalButton
                variant="secondary"
                size="sm"
                onClick={handleDownloadJson}
                icon={<FileCode className="w-3.5 h-3.5 text-slate-600" />}
              >
                Download Certificate (.cert.json)
              </OperationalButton>

              <OperationalButton
                variant="secondary"
                size="sm"
                onClick={handleVerifyNow}
                disabled={isVerifying}
                icon={<ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />}
              >
                Verify Certificate Integrity
              </OperationalButton>
            </div>

            {onNavigateToLedger && (
              <OperationalButton
                variant="ghost"
                size="sm"
                onClick={onNavigateToLedger}
                icon={<Database className="w-3.5 h-3.5 text-slate-500" />}
              >
                Inspect Block in Ledger
              </OperationalButton>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
