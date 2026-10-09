import React, { useState } from 'react';
import {
  Download,
  Key,
  ShieldCheck,
  Cpu,
  Layers,
  CheckCircle2,
  FileCheck2,
  AlertTriangle,
  Eye,
  Lock,
  ArrowRight,
  ExternalLink,
  Fingerprint,
  Terminal,
  Radio,
  FileText,
  BadgeAlert,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  FileSignature,
  Database,
  Search,
} from 'lucide-react';
import { Recipient, EncryptedPackage, DecryptionEvent, WatermarkPayload, UiMode } from '../types';
import { DistributionService } from '../services/distributionService';
import { GuidancePanel } from './ui/GuidancePanel';
import {
  WorkstationSurface,
  OperationalButton,
  StatusBadge,
  CryptoDataBlock,
  TechnicalMetricTile,
} from './ui/WorkstationPrimitives';

interface RecipientPortalProps {
  recipients: Recipient[];
  activePackage: EncryptedPackage | null;
  onDecryptionSuccess: (result: {
    recipient: Recipient;
    watermarkedText: string;
    decryptionEvent: DecryptionEvent;
    watermarkPayload: WatermarkPayload;
    blockHeight: number;
  }) => void;
  onSimulateLeak: (leakedText: string, metadata: { title: string; recipientName: string }) => void;
  onNavigateToForensics: () => void;
  onNavigateToLedger: () => void;
  uiMode?: UiMode;
}

export const RecipientPortal: React.FC<RecipientPortalProps> = ({
  recipients,
  activePackage,
  onDecryptionSuccess,
  onSimulateLeak,
  onNavigateToForensics,
  onNavigateToLedger,
  uiMode = 'workstation',
}) => {
  const [selectedRecipientId, setSelectedRecipientId] = useState<string>(recipients[0]?.id || '');
  const [isDecrypting, setIsDecrypting] = useState<boolean>(false);
  const [activeStep, setActiveStep] = useState<number>(0);
  const [revealStego, setRevealStego] = useState<boolean>(false);
  const [showRawSignature, setShowRawSignature] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const [decryptedResult, setDecryptedResult] = useState<{
    watermarkedText: string;
    decryptionEvent: DecryptionEvent;
    watermarkPayload: WatermarkPayload;
    blockHeight: number;
    blockHash: string;
    psnr: number;
    ssim: number;
  } | null>(null);

  const currentRecipient = recipients.find((r) => r.id === selectedRecipientId) || recipients[0];
  const hasEnvelope = activePackage?.envelopes.some((e) => e.recipientId === currentRecipient?.id);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleExecuteDecryption = async () => {
    if (!activePackage || !currentRecipient || !hasEnvelope) return;
    setIsDecrypting(true);
    setActiveStep(1);

    try {
      await new Promise((r) => setTimeout(r, 260));
      setActiveStep(2);
      await new Promise((r) => setTimeout(r, 300));
      setActiveStep(3);
      await new Promise((r) => setTimeout(r, 300));
      setActiveStep(4);
      await new Promise((r) => setTimeout(r, 320));
      setActiveStep(5);
      await new Promise((r) => setTimeout(r, 360));
      setActiveStep(6);

      const result = await DistributionService.executeRecipientDecryption(activePackage, currentRecipient);

      setDecryptedResult({
        watermarkedText: result.watermarkedText,
        decryptionEvent: result.decryptionEvent,
        watermarkPayload: result.watermarkPayload,
        blockHeight: result.blockHeight,
        blockHash: result.blockHash,
        psnr: result.psnrEstimate,
        ssim: result.ssimEstimate,
      });

      onDecryptionSuccess({
        recipient: currentRecipient,
        watermarkedText: result.watermarkedText,
        decryptionEvent: result.decryptionEvent,
        watermarkPayload: result.watermarkPayload,
        blockHeight: result.blockHeight,
      });
    } catch (err) {
      console.error('Decryption execution error:', err);
    } finally {
      setIsDecrypting(false);
      setActiveStep(0);
    }
  };

  const handleTriggerLeak = () => {
    if (!decryptedResult || !activePackage) return;
    onSimulateLeak(decryptedResult.watermarkedText, {
      title: activePackage.documentTitle,
      recipientName: currentRecipient.name,
    });
    onNavigateToForensics();
  };

  const handleDownloadDecrypted = () => {
    if (!decryptedResult) return;
    const blob = new Blob([decryptedResult.watermarkedText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentRecipient.name.toLowerCase().replace(/\s+/g, '_')}_decrypted.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const pipelineStages = [
    { num: 1, label: '01 ACCESS GATE', sub: 'Envelope Match' },
    { num: 2, label: '02 ML-KEM-768', sub: 'Decapsulation' },
    { num: 3, label: '03 AES-256-GCM', sub: 'Plaintext Recovery' },
    { num: 4, label: '04 STEGO BIND', sub: 'Session Fingerprint' },
    { num: 5, label: '05 ML-DSA-65', sub: 'Hardware Signing' },
    { num: 6, label: '06 DLT ANCHOR', sub: 'Consensus Finality' },
  ];

  return (
    <div className="space-y-6">
      {uiMode === 'guided' && (
        <GuidancePanel
          stepNumber="2"
          title="Recipient Verification, Decapsulation & Forensic Binding"
          summary="When an authorized recipient decrypts the document, the enclave unpacks the symmetric key via ML-KEM-768, injects a personalized zero-width watermark into the text, cryptographically signs the event with ML-DSA-65, and commits it into the air-gapped ledger."
          recommendedAction="Select 'Dr. Alice Vance' (Envelope Cleared) and click 'DECRYPT & BIND PROVENANCE EVENT'. Then try selecting 'Charlie Chen' to see unauthorized access rejection."
          whatToObserve="Observe the 6-stage operational pipeline execute in real-time, followed by the option to inspect the forensic stego channel or simulate a leak."
        />
      )}

      {/* 1. COMPACT RECIPIENT OPERATIONS CONTEXT HEADER */}
      <WorkstationSurface variant="primary" className="p-4 sm:p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status="active" icon={<Radio className="w-3.5 h-3.5 text-indigo-600" />}>
              RECIPIENT PORTAL
            </StatusBadge>
            <span className="text-[11px] font-mono text-slate-600 px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200">
              KEM: ML-KEM-768
            </span>
            <span className="text-[11px] font-mono text-slate-600 px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200">
              DSA: ML-DSA-65
            </span>
            <span className="text-[11px] font-mono text-emerald-700 px-2 py-0.5 rounded-md bg-emerald-50 border border-emerald-200">
              AIR-GAPPED 3/3 DLT
            </span>
          </div>

          <div className="text-xs font-mono text-slate-500">
            Enclave Status: <strong className="text-emerald-700">ONLINE</strong>
          </div>
        </div>
      </WorkstationSurface>

      {/* 2. OPERATOR IDENTITY & ACCESS GATE */}
      <WorkstationSurface variant="primary" className="p-4 sm:p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 pb-2.5 border-b border-slate-200 text-xs font-mono">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-slate-600" />
            <span className="font-semibold text-slate-900 uppercase tracking-wider">
              Operator Credential Register
            </span>
            <span className="text-slate-400 text-xs">
              ({recipients.length} Hardware Keystores Registered)
            </span>
          </div>
          <span className="text-xs text-slate-500 font-sans">
            Select operator profile to engage client keystore
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {recipients.map((recip) => {
            const isSelected = recip.id === selectedRecipientId;
            const inPackage = activePackage?.envelopes.some((e) => e.recipientId === recip.id);

            return (
              <div
                key={recip.id}
                onClick={() => {
                  setSelectedRecipientId(recip.id);
                  setDecryptedResult(null);
                  setRevealStego(false);
                }}
                className={`p-3.5 rounded-lg border cursor-pointer select-none transition-all ${
                  isSelected
                    ? 'border-indigo-400 bg-indigo-50/40 text-slate-900 shadow-2xs ring-1 ring-indigo-200'
                    : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                }`}
              >
                <div className="flex items-center justify-between text-xs font-mono mb-1.5">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                    isSelected ? 'bg-indigo-600 text-white' : 'bg-slate-100 text-slate-600'
                  }`}>
                    {recip.avatarInitials}
                  </span>

                  {inPackage ? (
                    <span className="text-[10px] text-emerald-700 font-semibold flex items-center gap-1 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">
                      <CheckCircle2 className="w-2.5 h-2.5" /> CLEARED
                    </span>
                  ) : (
                    <span className="text-[10px] text-rose-700 font-semibold flex items-center gap-1 bg-rose-50 px-1.5 py-0.5 rounded border border-rose-200">
                      NO ENVELOPE
                    </span>
                  )}
                </div>

                <div className="font-semibold text-xs text-slate-900 truncate">
                  {recip.name}
                </div>
                <div className="text-[11px] text-slate-500 truncate font-mono mt-0.5">
                  {recip.role} &bull; {recip.clearanceLevel}
                </div>
                <div className="text-[10px] text-slate-400 font-mono truncate mt-1">
                  FP: {recip.keys.keyFingerprint.slice(0, 16)}...
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Operator & Access Banner */}
        <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="text-slate-500">ACTIVE CREDENTIAL:</span>
            <span className="text-slate-900 font-bold">{currentRecipient.name} ({currentRecipient.id})</span>
            <span className="text-slate-300 hidden sm:inline">&bull;</span>
            <span className="text-slate-500">CLEARANCE:</span>
            <span className="text-slate-800 font-semibold">{currentRecipient.clearanceLevel}</span>
          </div>

          <div className="shrink-0 flex items-center gap-2">
            <span className="text-slate-500">ACCESS GATE:</span>
            {hasEnvelope ? (
              <span className="px-2.5 py-1 rounded-md bg-emerald-50 border border-emerald-200 text-emerald-800 font-bold flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                AUTHORIZED FOR DECRYPTION
              </span>
            ) : (
              <span className="px-2.5 py-1 rounded-md bg-rose-50 border border-rose-200 text-rose-800 font-bold flex items-center gap-1.5">
                <BadgeAlert className="w-3.5 h-3.5 text-rose-600" />
                ACCESS REJECTED (NO ENVELOPE)
              </span>
            )}
          </div>
        </div>
      </WorkstationSurface>

      {/* 3. EXECUTION DISPATCH BAR & PIPELINE */}
      <WorkstationSurface variant="elevated" className="p-4 sm:p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-slate-500 uppercase font-bold">INBOUND PACKAGE MANIFEST:</span>
              <span className="text-slate-900 font-semibold">
                {activePackage ? activePackage.packageId : 'NO PACKAGE LOADED'}
              </span>
              {activePackage && (
                <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 text-xs">
                  {activePackage.documentTitle}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 leading-tight">
              Executing decapsulation will bind an invisible session watermark to your clearance profile and sign the
              immutable DLT provenance record.
            </p>
          </div>

          <div className="shrink-0">
            <OperationalButton
              variant={hasEnvelope ? 'operational' : 'secondary'}
              size="lg"
              onClick={handleExecuteDecryption}
              disabled={!activePackage || !hasEnvelope || isDecrypting}
              icon={<Cpu className="w-4 h-4" />}
              data-tour-target="decrypt-recipient-btn"
            >
              {isDecrypting
                ? 'EXECUTING CRYPTOGRAPHIC PIPELINE...'
                : decryptedResult
                ? 'RE-EXECUTE DECRYPTION & BIND PROVENANCE'
                : 'DECRYPT & BIND PROVENANCE EVENT'}
            </OperationalButton>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-xs font-mono pt-1">
          {pipelineStages.map((st) => {
            const isExecuting = isDecrypting && activeStep === st.num;
            const isCompleted = (isDecrypting && activeStep > st.num) || (decryptedResult !== null && !isDecrypting);
            const isFailed = !hasEnvelope && st.num === 1;

            return (
              <div
                key={`pipeline-stage-${st.num}`}
                className={`p-2.5 rounded-lg border transition-all ${
                  isExecuting
                    ? 'bg-indigo-50 border-indigo-300 shadow-2xs'
                    : isCompleted
                    ? 'bg-white border-slate-200 text-slate-700'
                    : isFailed
                    ? 'bg-rose-50 border-rose-200 text-rose-700'
                    : 'bg-slate-50 border-slate-200 text-slate-400'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] mb-1">
                  <span className={isExecuting ? 'text-indigo-700 font-bold' : isCompleted ? 'text-emerald-700 font-semibold' : 'text-slate-400'}>
                    {isCompleted ? '✓ CLEARED' : isExecuting ? 'PROCESSING' : isFailed ? 'BLOCKED' : 'PENDING'}
                  </span>
                  {isExecuting && <span className="w-2 h-2 rounded-full bg-indigo-600 animate-pulse" />}
                </div>

                <div className="font-semibold text-xs text-slate-900 truncate">
                  {st.label}
                </div>
                <div className="text-[10px] text-slate-500 truncate mt-0.5">
                  {st.sub}
                </div>
              </div>
            );
          })}
        </div>
      </WorkstationSurface>

      {/* 4. POST-DECRYPTION WORKSPACE */}
      {decryptedResult ? (
        <div className="space-y-6">
          <WorkstationSurface variant="primary" className="p-0 overflow-hidden border-slate-200">
            <div className="p-4 bg-slate-50 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <FileCheck2 className="w-5 h-5 text-indigo-600 shrink-0" />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                      SECURE DOCUMENT VIEWPORT
                    </span>
                    <span className="px-2 py-0.5 rounded bg-rose-50 border border-rose-200 text-rose-700 text-[10px] font-mono font-bold">
                      TOP SECRET // SCI
                    </span>
                    <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-700 text-[10px] font-mono">
                      ID: {decryptedResult.decryptionEvent.watermarkId.slice(0, 10)}
                    </span>
                  </div>
                  <div className="text-xs font-mono text-slate-500 mt-0.5">
                    TITLE: {activePackage?.documentTitle} &bull; AUTHORIZED VIEWER: {currentRecipient.name}
                  </div>
                </div>
              </div>

              <div className="shrink-0 flex items-center gap-2">
                <OperationalButton
                  variant="secondary"
                  size="sm"
                  onClick={() => setRevealStego(!revealStego)}
                  icon={<Eye className={`w-3.5 h-3.5 ${revealStego ? 'text-sky-600' : 'text-slate-600'}`} />}
                >
                  {revealStego ? 'CLOSE STEGO CHANNEL' : 'INSPECT STEGO CHANNEL'}
                </OperationalButton>
              </div>
            </div>

            {revealStego && (
              <div className="p-4 bg-sky-50/70 border-b border-sky-200 text-xs font-mono text-sky-900 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold uppercase tracking-wider flex items-center gap-1.5 text-sky-800">
                    <Fingerprint className="w-4 h-4 text-sky-600" />
                    FORENSIC CHANNEL INSPECTION ACTIVE
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-white border border-sky-200 text-sky-700 font-semibold">
                    DIAGNOSTIC TELEMETRY
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs pt-1">
                  <div className="p-2.5 rounded-lg bg-white border border-sky-200">
                    <span className="text-slate-400 block text-[10px] uppercase font-semibold">SESSION UUID</span>
                    <span className="break-all font-semibold text-slate-800">{decryptedResult.watermarkPayload.sessionId}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-white border border-sky-200">
                    <span className="text-slate-400 block text-[10px] uppercase font-semibold">WATERMARK IDENTIFIER</span>
                    <span className="break-all font-semibold text-slate-800">{decryptedResult.watermarkPayload.watermarkId}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-white border border-sky-200">
                    <span className="text-slate-400 block text-[10px] uppercase font-semibold">RECIPIENT FINGERPRINT</span>
                    <span className="break-all font-semibold text-slate-800">{decryptedResult.watermarkPayload.recipientFingerprint}</span>
                  </div>
                </div>
                <p className="text-xs text-sky-800 leading-relaxed font-sans">
                  The document displayed below remains 100% human-readable and visually identical to other recipients.
                  The cryptographic payload is encoded steganographically into whitespace entropy, ready for forensic recovery.
                </p>
              </div>
            )}

            <div className="p-6 font-mono text-xs text-slate-800 bg-white leading-relaxed max-h-96 overflow-y-auto whitespace-pre-wrap select-text border-b border-slate-200">
              {decryptedResult.watermarkedText}
            </div>

            <div className="p-3.5 bg-slate-50 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
              <div className="flex items-center gap-2 text-slate-600 text-xs">
                <FileSignature className="w-4 h-4 text-emerald-600" />
                <span>
                  Plaintext decrypted via CEK &bull; Bound to {currentRecipient.name}&apos;s hardware keystore
                </span>
              </div>

              <div className="flex items-center gap-2">
                <OperationalButton
                  variant="secondary"
                  size="sm"
                  onClick={handleDownloadDecrypted}
                  icon={<Download className="w-3.5 h-3.5 text-slate-600" />}
                >
                  Download Decrypted Copy (.txt)
                </OperationalButton>

                <OperationalButton
                  variant="danger"
                  size="sm"
                  onClick={handleTriggerLeak}
                  icon={<AlertTriangle className="w-3.5 h-3.5" />}
                  data-tour-target="simulate-leak-btn"
                >
                  Simulate Leak of {currentRecipient.name}&apos;s Copy
                </OperationalButton>
              </div>
            </div>
          </WorkstationSurface>

          {/* FORMAL DECRYPTION PROVENANCE */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-7 space-y-4">
              <WorkstationSurface variant="elevated" className="space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-slate-200">
                  <span className="font-semibold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-600" />
                    Decryption Provenance Record
                  </span>
                  <span className="text-[10px] text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 font-bold">
                    RATIFIED BY CONSENSUS
                  </span>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between items-center">
                    <span className="text-slate-500">EVENT IDENTIFIER:</span>
                    <span className="text-slate-900 font-bold">{decryptedResult.decryptionEvent.eventId}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between items-center">
                    <span className="text-slate-500">RECIPIENT SIGNER:</span>
                    <span className="text-slate-800">{currentRecipient.name} ({currentRecipient.id})</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between items-center">
                    <span className="text-slate-500">WATERMARK COMMITMENT:</span>
                    <span className="text-slate-800 truncate max-w-[240px]">
                      {decryptedResult.decryptionEvent.watermarkCommitment}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between items-center">
                    <span className="text-slate-500">DLT ANCHOR REFERENCE:</span>
                    <span className="text-emerald-700 font-bold">
                      Block #{decryptedResult.blockHeight} &bull; {decryptedResult.blockHash.slice(0, 16)}...
                    </span>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-200 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-500 uppercase font-semibold">RECIPIENT ML-DSA-65 SIGNATURE:</span>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => handleCopy(decryptedResult.decryptionEvent.recipientSignatureBase64, 'dsa-sig')}
                        className="text-xs text-slate-600 hover:text-slate-900 flex items-center gap-1 cursor-pointer font-medium"
                      >
                        {copiedKey === 'dsa-sig' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                        {copiedKey === 'dsa-sig' ? 'Copied' : 'Copy'}
                      </button>
                      <button
                        type="button"
                        onClick={() => setShowRawSignature(!showRawSignature)}
                        className="text-xs text-slate-600 hover:text-slate-900 flex items-center gap-0.5 cursor-pointer font-medium"
                      >
                        {showRawSignature ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        {showRawSignature ? 'Collapse' : 'Expand'}
                      </button>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-700 break-all leading-relaxed">
                    {showRawSignature
                      ? decryptedResult.decryptionEvent.recipientSignatureBase64
                      : `${decryptedResult.decryptionEvent.recipientSignatureBase64.slice(0, 72)}...`}
                  </div>
                </div>
              </WorkstationSurface>
            </div>

            <div className="lg:col-span-5 space-y-4">
              <WorkstationSurface variant="elevated" className="space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-slate-200">
                  <span className="font-semibold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                    <Database className="w-4 h-4 text-slate-600" />
                    Visual Invariance &amp; DLT Proof
                  </span>
                  <button
                    type="button"
                    onClick={onNavigateToLedger}
                    className="text-xs text-indigo-600 hover:text-indigo-800 flex items-center gap-1 cursor-pointer font-medium"
                  >
                    <span>DLT Explorer</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-2.5">
                  <TechnicalMetricTile
                    label="SSIM INDEX"
                    value={decryptedResult.ssim}
                    subValue="Mathematical Equivalence"
                    status="nominal"
                  />
                  <TechnicalMetricTile
                    label="STEGO PSNR"
                    value={`${decryptedResult.psnr} dB`}
                    subValue="Imperceptible Carrier"
                    status="nominal"
                  />
                  <TechnicalMetricTile
                    label="LEDGER BLOCK"
                    value={`#${decryptedResult.blockHeight}`}
                    subValue="Finality Anchored"
                    status="nominal"
                  />
                  <TechnicalMetricTile
                    label="QUORUM STATE"
                    value="3/3 VALID"
                    subValue="Air-Gap Consensus"
                    status="nominal"
                  />
                </div>

                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 leading-relaxed font-sans">
                  <strong className="text-slate-900 font-semibold font-mono">Verification Guarantee:</strong> While this document appears
                  visually identical to human readers and OCR engines (SSIM: {decryptedResult.ssim}), its hidden
                  steganographic encoding guarantees 100% mathematical non-repudiation if leaked.
                </div>
              </WorkstationSurface>
            </div>
          </div>
        </div>
      ) : (
        <WorkstationSurface variant="recessed" className="p-8 text-center space-y-3 font-mono">
          <div className="w-12 h-12 rounded-xl bg-white border border-slate-200 shadow-2xs flex items-center justify-center mx-auto text-slate-600">
            <Lock className="w-5 h-5 text-indigo-600" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-900">
              Workstation Awaiting Cryptographic Decryption Trigger
            </h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 leading-relaxed font-sans">
              Verify your operator credential clearance above. When authorized, click &apos;Decrypt &amp; Bind Provenance Event&apos;
              to decapsulate the Content Encryption Key via ML-KEM-768 and commit the signed event to the ledger.
            </p>
          </div>

          <div className="pt-2">
            <span className="inline-flex items-center gap-1.5 text-xs text-slate-700 px-3 py-1 rounded-md bg-white border border-slate-200 shadow-2xs">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
              Client Enclave Ready &bull; Zero Server Knowledge
            </span>
          </div>
        </WorkstationSurface>
      )}
    </div>
  );
};
