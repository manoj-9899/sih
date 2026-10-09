import React, { useState } from 'react';
import {
  Upload,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  FileCode,
  HardDrive,
  Mail,
  Cloud,
  Layers,
  ArrowRight,
  RefreshCw,
  Lock,
  UserCheck,
  UserX,
  FileWarning,
} from 'lucide-react';
import {
  EncryptedPackage,
  PackageValidationResult,
  Recipient,
  SihpkgValidationStatus,
} from '../types';
import { PackageExportService, TRAILER_SIZE } from '../services/packageExportService';
import { sessionManager, AuthenticatedSession } from '../crypto/sessionManager';
import { PrimaryButton, SecondaryButton, DangerButton } from './ui/designSystem';

interface SihpkgImportSectionProps {
  recipients: Recipient[];
  activeSession: AuthenticatedSession | null;
  onPackageImported: (pkg: EncryptedPackage) => void;
  currentPackage: EncryptedPackage | null;
}

export const SihpkgImportSection: React.FC<SihpkgImportSectionProps> = ({
  recipients,
  activeSession,
  onPackageImported,
  currentPackage,
}) => {
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<PackageValidationResult | null>(null);
  const [importedFileName, setImportedFileName] = useState<string>('');
  const [simulatedChannel, setSimulatedChannel] = useState<'USB' | 'EMAIL' | 'CLOUD' | 'AIRGAP' | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const processBinaryFile = async (bytes: Uint8Array, fileName: string) => {
    setIsValidating(true);
    setImportedFileName(fileName);
    setValidationResult(null);

    try {
      // Allow visual animation of validation stages
      await new Promise((r) => setTimeout(r, 220));

      const result = await PackageExportService.validateAndImportPackage(
        bytes,
        activeSession?.userId,
        activeSession
      );

      setValidationResult(result);

      if (result.isValid && result.package) {
        onPackageImported(result.package);
      }
    } catch (err: any) {
      setValidationResult({
        isValid: false,
        status: 'CORRUPTED_PACKAGE',
        errorMessage: err.message || 'Fatal error processing .sihpkg file.',
        validationSteps: [
          { name: 'Package Parser', passed: false, detail: err.message || 'Exception during parsing.' },
        ],
      });
    } finally {
      setIsValidating(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const buffer = event.target?.result as ArrayBuffer;
      if (buffer) {
        processBinaryFile(new Uint8Array(buffer), file.name);
      }
    };
    reader.readAsArrayBuffer(file);
    e.target.value = '';
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const buffer = event.target?.result as ArrayBuffer;
      if (buffer) {
        processBinaryFile(new Uint8Array(buffer), file.name);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  // Quick Simulation Test 1: Simulate untrusted transport import
  const handleSimulateTransport = async (channel: 'USB' | 'EMAIL' | 'CLOUD' | 'AIRGAP') => {
    if (!currentPackage) return;
    setSimulatedChannel(channel);
    try {
      const binary = await PackageExportService.exportPackageToBinary(currentPackage);
      await processBinaryFile(binary, `${currentPackage.documentTitle.replace(/\s+/g, '_')}_transport_${channel.toLowerCase()}.sihpkg`);
    } catch (err: any) {
      console.error('Transport simulation failed:', err);
    }
  };

  // Quick Attack Test: Tamper with ciphertext payload
  const handleSimulatePayloadTamper = async () => {
    if (!currentPackage) return;
    try {
      const binary = await PackageExportService.exportPackageToBinary(currentPackage);
      const tampered = new Uint8Array(binary);
      // Flip byte in ciphertext area
      const targetIdx = tampered.length - TRAILER_SIZE - 4;
      tampered[targetIdx] = tampered[targetIdx] ^ 0xee;

      await processBinaryFile(tampered, `${currentPackage.documentTitle}_tampered_payload.sihpkg`);
    } catch (err: any) {
      console.error('Tamper simulation failed:', err);
    }
  };

  // Quick Attack Test: Tamper with manifest document ID
  const handleSimulateManifestTamper = async () => {
    if (!currentPackage) return;
    try {
      const binary = await PackageExportService.exportPackageToBinary(currentPackage);
      const tampered = new Uint8Array(binary);
      // Flip byte inside manifest
      tampered[32] = tampered[32] ^ 0xff;

      await processBinaryFile(tampered, `${currentPackage.documentTitle}_tampered_manifest.sihpkg`);
    } catch (err: any) {
      console.error('Manifest tamper simulation failed:', err);
    }
  };

  const getStatusBadge = (status: SihpkgValidationStatus) => {
    switch (status) {
      case 'VALID':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
            VALID CONTAINER
          </span>
        );
      case 'PACKAGE_INTEGRITY_FAILURE':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-300">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
            PACKAGE_INTEGRITY_FAILURE
          </span>
        );
      case 'PAYLOAD_INTEGRITY_FAILURE':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-300">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
            PAYLOAD_INTEGRITY_FAILURE
          </span>
        );
      case 'DOCUMENT_BINDING_FAILURE':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-300">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
            DOCUMENT_BINDING_FAILURE
          </span>
        );
      case 'ENVELOPE_INTEGRITY_FAILURE':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-300">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
            ENVELOPE_INTEGRITY_FAILURE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-100 text-amber-800 border border-amber-300">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
            {status}
          </span>
        );
    }
  };

  return (
    <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-700">
            <FileCode className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-bold font-mono tracking-wider text-slate-900 uppercase">
              Secure Portable Package (.sihpkg) Ingestion
            </h3>
            <p className="text-[11px] text-slate-500">
              Untrusted transport container with NIST FIPS 203 ML-KEM-768 envelopes. Zero plaintext exposure.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500 bg-slate-50 px-2 py-1 rounded border border-slate-200">
          <Lock className="w-3 h-3 text-emerald-600" />
          <span>CRYPTOGRAPHIC BOUNDARY ENFORCED</span>
        </div>
      </div>

      {/* Drop Zone & File Selector */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`border-2 border-dashed rounded-xl p-6 text-center transition-all cursor-pointer ${
          isDragging
            ? 'border-indigo-500 bg-indigo-50/50 scale-[1.005]'
            : 'border-slate-300 hover:border-indigo-400 bg-slate-50/60 hover:bg-slate-50'
        }`}
        onClick={() => document.getElementById('sihpkg-file-input')?.click()}
      >
        <input
          id="sihpkg-file-input"
          type="file"
          accept=".sihpkg"
          onChange={handleFileChange}
          className="hidden"
        />
        <div className="flex flex-col items-center justify-center space-y-2">
          <div className="w-10 h-10 rounded-full bg-indigo-100/70 border border-indigo-200 flex items-center justify-center text-indigo-700">
            <Upload className="w-5 h-5" />
          </div>
          <div className="text-xs font-medium text-slate-800">
            Drag and drop <span className="font-mono font-bold text-indigo-700">.sihpkg</span> package here, or click to browse
          </div>
          <div className="text-[11px] text-slate-500 max-w-md">
            Import an encrypted package received via USB flash drive, email attachment, LAN transfer, or cloud bucket.
          </div>
        </div>
      </div>

      {/* Untrusted Channel Simulation Bar */}
      {currentPackage && (
        <div className="p-3 bg-slate-50/80 rounded-lg border border-slate-200 text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-700 flex items-center gap-1.5">
              <HardDrive className="w-3.5 h-3.5 text-slate-500" />
              Simulate Untrusted Transport Transfer:
            </span>
            <span className="text-[10px] text-slate-400 font-mono">Channel does not need to be trusted</span>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <button
              type="button"
              onClick={() => handleSimulateTransport('USB')}
              disabled={isValidating}
              className="px-2.5 py-1.5 rounded-md bg-white border border-slate-200 text-[11px] text-slate-700 hover:bg-slate-100 hover:border-slate-300 flex items-center gap-1.5 cursor-pointer shadow-2xs"
            >
              <HardDrive className="w-3 h-3 text-slate-600" />
              <span>USB Flash Drive</span>
            </button>

            <button
              type="button"
              onClick={() => handleSimulateTransport('EMAIL')}
              disabled={isValidating}
              className="px-2.5 py-1.5 rounded-md bg-white border border-slate-200 text-[11px] text-slate-700 hover:bg-slate-100 hover:border-slate-300 flex items-center gap-1.5 cursor-pointer shadow-2xs"
            >
              <Mail className="w-3 h-3 text-slate-600" />
              <span>Email Attachment</span>
            </button>

            <button
              type="button"
              onClick={() => handleSimulateTransport('CLOUD')}
              disabled={isValidating}
              className="px-2.5 py-1.5 rounded-md bg-white border border-slate-200 text-[11px] text-slate-700 hover:bg-slate-100 hover:border-slate-300 flex items-center gap-1.5 cursor-pointer shadow-2xs"
            >
              <Cloud className="w-3 h-3 text-slate-600" />
              <span>Cloud Object Storage</span>
            </button>

            <button
              type="button"
              onClick={handleSimulatePayloadTamper}
              disabled={isValidating}
              className="px-2.5 py-1.5 rounded-md bg-rose-50 border border-rose-200 text-[11px] text-rose-700 hover:bg-rose-100 flex items-center gap-1.5 cursor-pointer shadow-2xs ml-auto"
            >
              <ShieldAlert className="w-3 h-3 text-rose-600" />
              <span>Test Tampered Payload Attack</span>
            </button>
          </div>
        </div>
      )}

      {/* Validation Results Drawer */}
      {isValidating && (
        <div className="p-4 rounded-xl bg-indigo-50/60 border border-indigo-200 flex items-center gap-3 text-xs text-indigo-900">
          <RefreshCw className="w-4 h-4 text-indigo-600 animate-spin shrink-0" />
          <span>Validating .sihpkg container structure, checksum trailer, and post-quantum envelopes...</span>
        </div>
      )}

      {validationResult && (
        <div
          className={`p-4 rounded-xl border text-xs space-y-3 ${
            validationResult.isValid
              ? 'bg-emerald-50/60 border-emerald-200 text-emerald-950'
              : 'bg-rose-50/60 border-rose-200 text-rose-950'
          }`}
        >
          {/* Status Title Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              {validationResult.isValid ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
              ) : (
                <XCircle className="w-5 h-5 text-rose-600 shrink-0" />
              )}
              <span className="font-bold text-slate-900 text-sm">
                {validationResult.isValid ? 'Package Validated Successfully' : 'Package Validation Rejected'}
              </span>
            </div>
            <div>{getStatusBadge(validationResult.status)}</div>
          </div>

          {/* Error Message if rejected */}
          {!validationResult.isValid && (
            <div className="p-3 bg-white rounded-lg border border-rose-200 text-rose-800 text-xs space-y-1">
              <strong className="block text-rose-900 font-semibold">Security Alert:</strong>
              <p>{validationResult.errorMessage || 'Invalid or corrupted SIHPKG package.'}</p>
            </div>
          )}

          {/* Recipient Authorization Isolation Result */}
          {validationResult.isValid && validationResult.recipientAuthorization && (
            <div className="p-3 bg-white rounded-lg border border-slate-200 text-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-800 flex items-center gap-1.5">
                  <UserCheck className="w-4 h-4 text-indigo-600" />
                  Recipient Authorization Check
                </span>
                {validationResult.recipientAuthorization.canDecrypt ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                    AUTHORIZED TO DECRYPT
                  </span>
                ) : validationResult.recipientAuthorization.status === 'REVOKED' ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-200">
                    ACCESS REVOKED
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-200">
                    UNAUTHORIZED RECIPIENT
                  </span>
                )}
              </div>

              <div className="text-[11px] text-slate-600">
                {validationResult.recipientAuthorization.reason}
              </div>

              {/* List of all authorized recipients in container */}
              {validationResult.manifest && (
                <div className="pt-2 border-t border-slate-100">
                  <span className="text-[10px] font-mono font-semibold text-slate-500 uppercase block mb-1">
                    Enclave Envelopes ({validationResult.manifest.recipients.length} Recipients):
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    {validationResult.manifest.recipients.map((recip) => {
                      const isCurrentUser = recip.recipientId === activeSession?.userId;
                      return (
                        <div
                          key={recip.recipientId}
                          className={`p-2 rounded border text-[11px] flex items-center justify-between ${
                            isCurrentUser
                              ? 'bg-indigo-50/70 border-indigo-200 font-medium text-slate-900'
                              : 'bg-slate-50 border-slate-200 text-slate-600'
                          }`}
                        >
                          <div className="truncate">
                            <span>{recip.recipientName}</span>
                            {isCurrentUser && <span className="ml-1 text-[10px] text-indigo-600 font-bold">(You)</span>}
                          </div>
                          <span
                            className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${
                              recip.status === 'REVOKED'
                                ? 'bg-rose-100 text-rose-800'
                                : 'bg-emerald-100 text-emerald-800'
                            }`}
                          >
                            {recip.status}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Validation Stages List */}
          <div className="space-y-1 pt-1">
            <span className="text-[10px] font-mono font-semibold text-slate-500 uppercase block">
              Validation Evidence Pipeline:
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
              {validationResult.validationSteps.map((step, idx) => (
                <div
                  key={idx}
                  className={`p-2 rounded text-[11px] flex items-center gap-2 border ${
                    step.passed
                      ? 'bg-emerald-50/40 border-emerald-200 text-emerald-900'
                      : 'bg-rose-50/50 border-rose-200 text-rose-900'
                  }`}
                >
                  {step.passed ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  ) : (
                    <XCircle className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                  )}
                  <span className="truncate">{step.detail}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
