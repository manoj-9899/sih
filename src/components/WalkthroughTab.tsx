import React, { useState } from 'react';
import {
  PlayCircle,
  ArrowRight,
  ShieldCheck,
  Lock,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Sparkles,
  Layers,
  Eye,
  FileCheck2,
  Copy,
  Check,
  Terminal,
  Search,
  Fingerprint,
  Radio,
} from 'lucide-react';
import {
  ClassifiedDocument,
  Recipient,
  EncryptedPackage,
  DecryptionEvent,
  ForensicAttributionReport,
  UiMode,
} from '../types';
import { DistributionService } from '../services/distributionService';
import { GuidancePanel } from './ui/GuidancePanel';
import {
  WorkstationSurface,
  OperationalButton,
  StatusBadge,
  CryptoDataBlock,
  TechnicalMetricTile,
} from './ui/WorkstationPrimitives';

interface WalkthroughTabProps {
  documents: ClassifiedDocument[];
  recipients: Recipient[];
  onFinishDemo: () => void;
  uiMode?: UiMode;
}

export const WalkthroughTab: React.FC<WalkthroughTabProps> = ({
  documents,
  recipients,
  onFinishDemo,
  uiMode = 'workstation',
}) => {
  const [currentStep, setCurrentStep] = useState<number>(1);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [inspectStegoAlice, setInspectStegoAlice] = useState<boolean>(false);
  const [inspectStegoBob, setInspectStegoBob] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Demo state variables
  const [demoPackage, setDemoPackage] = useState<EncryptedPackage | null>(null);
  const [aliceDecrypted, setAliceDecrypted] = useState<{
    text: string;
    event: DecryptionEvent;
    blockHeight: number;
  } | null>(null);
  const [bobDecrypted, setBobDecrypted] = useState<{
    text: string;
    event: DecryptionEvent;
    blockHeight: number;
  } | null>(null);
  const [investigationReport, setInvestigationReport] = useState<ForensicAttributionReport | null>(null);

  const alice = recipients.find((r) => r.id === 'USR-ALICE-VANCE-01') || recipients[0];
  const bob = recipients.find((r) => r.id === 'USR-BOB-MARTINEZ-02') || recipients[1];
  const charlie = recipients.find((r) => r.id === 'USR-CHARLIE-CHEN-03') || recipients[2];
  const targetDoc = documents[0];

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleStep1_Encrypt = async () => {
    setIsRunning(true);
    try {
      const pkg = await DistributionService.createEncryptedPackage(targetDoc, [alice, bob, charlie]);
      setDemoPackage(pkg);
      setCurrentStep(2);
    } catch (err) {
      console.error(err);
    } finally {
      setIsRunning(false);
    }
  };

  const handleStep2_AliceDecrypt = async () => {
    if (!demoPackage) return;
    setIsRunning(true);
    try {
      const res = await DistributionService.executeRecipientDecryption(demoPackage, alice);
      setAliceDecrypted({
        text: res.watermarkedText,
        event: res.decryptionEvent,
        blockHeight: res.blockHeight,
      });
      setCurrentStep(3);
    } catch (err) {
      console.error(err);
    } finally {
      setIsRunning(false);
    }
  };

  const handleStep3_BobDecrypt = async () => {
    if (!demoPackage) return;
    setIsRunning(true);
    try {
      const res = await DistributionService.executeRecipientDecryption(demoPackage, bob);
      setBobDecrypted({
        text: res.watermarkedText,
        event: res.decryptionEvent,
        blockHeight: res.blockHeight,
      });
      setCurrentStep(4);
    } catch (err) {
      console.error(err);
    } finally {
      setIsRunning(false);
    }
  };

  const handleStep4_VisualCheck = () => {
    setCurrentStep(5);
  };

  const handleStep5_Attribution = async () => {
    if (!bobDecrypted) return;
    setIsRunning(true);
    try {
      const report = await DistributionService.investigateLeakedDocument(bobDecrypted.text);
      setInvestigationReport(report);
      setCurrentStep(6);
    } catch (err) {
      console.error(err);
    } finally {
      setIsRunning(false);
    }
  };

  const handleResetDemo = () => {
    setCurrentStep(1);
    setDemoPackage(null);
    setAliceDecrypted(null);
    setBobDecrypted(null);
    setInvestigationReport(null);
    setInspectStegoAlice(false);
    setInspectStegoBob(false);
  };

  const handleRunFullPipeline = async () => {
    if (isRunning) return;
    setIsRunning(true);
    try {
      const pkg = await DistributionService.createEncryptedPackage(targetDoc, [alice, bob, charlie]);
      setDemoPackage(pkg);
      setCurrentStep(2);
      await new Promise((r) => setTimeout(r, 600));

      const aRes = await DistributionService.executeRecipientDecryption(pkg, alice);
      setAliceDecrypted({ text: aRes.watermarkedText, event: aRes.decryptionEvent, blockHeight: aRes.blockHeight });
      setCurrentStep(3);
      await new Promise((r) => setTimeout(r, 600));

      const bRes = await DistributionService.executeRecipientDecryption(pkg, bob);
      setBobDecrypted({ text: bRes.watermarkedText, event: bRes.decryptionEvent, blockHeight: bRes.blockHeight });
      setCurrentStep(4);
      await new Promise((r) => setTimeout(r, 600));

      setCurrentStep(5);
      await new Promise((r) => setTimeout(r, 600));

      const report = await DistributionService.investigateLeakedDocument(bRes.watermarkedText);
      setInvestigationReport(report);
      setCurrentStep(6);
    } catch (e) {
      console.error(e);
    } finally {
      setIsRunning(false);
    }
  };

  const stages = [
    { num: 1, title: 'Lock Document', desc: '1 safe with separate keys' },
    { num: 2, title: 'Alice Opens File', desc: "Stamps Alice's secret watermark" },
    { num: 3, title: 'Bob Opens File', desc: "Stamps Bob's secret watermark" },
    { num: 4, title: 'Visual Check', desc: 'Documents look 100% identical' },
    { num: 5, title: 'Scan Leaked Copy', desc: 'Bob caught with 100% proof' },
  ];

  return (
    <div className="space-y-6">
      {uiMode === 'guided' && (
        <GuidancePanel
          stepNumber="★"
          title="Interactive Detective Story Walkthrough"
          summary="Watch how secret documents are protected, watermarked, and traced: 1. Put the file into a quantum-proof digital safe, 2. Alice opens her copy and gets an invisible watermark, 3. Bob opens his copy and gets his own watermark, 4. Both copies look 100% identical, 5. Bob leaks his copy online, and 6. Our scanner catches Bob with 100% proof."
          recommendedAction="Click 'AUTO-PLAY FULL DETECTIVE STORY' to watch the entire process run automatically, or step through each stage manually below."
          whatToObserve="Notice how Bob is caught immediately, even though his leaked document looks exactly like Alice's copy."
          actionButtonLabel="Auto-Play Detective Story"
          onActionClick={handleRunFullPipeline}
        />
      )}

      {/* 1. MISSION HEADER & OPERATIONAL CONTEXT */}
      <WorkstationSurface variant="primary" className="p-4 sm:p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status="active" icon={<Radio className="w-3.5 h-3.5 text-indigo-600" />}>
              MISSION CONSOLE
            </StatusBadge>
            <span className="text-[11px] font-mono text-slate-600 px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200">
              ML-KEM-768
            </span>
            <span className="text-[11px] font-mono text-slate-600 px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200">
              ML-DSA-65
            </span>
            <span className="text-[11px] font-mono text-emerald-700 px-2 py-0.5 rounded-md bg-emerald-50 border border-emerald-200">
              AIR-GAPPED 3/3 DLT
            </span>
          </div>

          <div className="shrink-0 flex items-center gap-2">
            {currentStep > 1 && (
              <OperationalButton
                variant="secondary"
                size="sm"
                onClick={handleResetDemo}
                disabled={isRunning}
                icon={<RotateCcw className="w-3 h-3" />}
              >
                Reset
              </OperationalButton>
            )}

            <OperationalButton
              variant="operational"
              size="sm"
              onClick={handleRunFullPipeline}
              disabled={isRunning}
              icon={<PlayCircle className="w-3.5 h-3.5" />}
            >
              {isRunning ? 'EXECUTING STORY...' : 'AUTO-PLAY DETECTIVE STORY'}
            </OperationalButton>
          </div>
        </div>
      </WorkstationSurface>

      {/* 2. LIFECYCLE TIMELINE */}
      <WorkstationSurface variant="recessed" className="p-3 sm:p-4">
        <div className="flex items-center justify-between pb-2.5 mb-2.5 border-b border-slate-200 text-xs font-mono text-slate-500">
          <span className="uppercase font-semibold tracking-wider flex items-center gap-2">
            <Layers className="w-4 h-4 text-slate-700" />
            Lifecycle Pipeline Progress
          </span>
          <span>
            Stage {Math.min(currentStep, 5)} of 5 &bull;{' '}
            <strong className={currentStep === 6 ? 'text-emerald-700 font-bold' : 'text-slate-900 font-bold'}>
              {currentStep === 6 ? 'ALL PROOFS RESOLVED' : isRunning ? 'PROCESSING' : 'READY'}
            </strong>
          </span>
        </div>

        <div className="flex items-stretch gap-2.5 overflow-x-auto pb-1 sm:pb-0">
          {stages.map((st) => {
            const isCompleted = currentStep > st.num || currentStep === 6;
            const isCurrent = currentStep === st.num;

            return (
              <div
                key={`stage-timeline-${st.num}`}
                className={`flex-1 min-w-[175px] sm:min-w-0 p-3 rounded-lg border transition-all select-none ${
                  isCurrent
                    ? 'bg-white border-indigo-400 shadow-sm ring-1 ring-indigo-200'
                    : isCompleted
                    ? 'bg-white border-slate-200 shadow-2xs'
                    : 'bg-slate-100/60 border-slate-200/60 opacity-60'
                }`}
              >
                <div className="flex items-center justify-between gap-1 mb-1.5">
                  <div className="flex items-center gap-1.5 font-mono text-xs">
                    <span
                      className={`w-4 h-4 rounded flex items-center justify-center text-[10px] font-bold ${
                        isCurrent
                          ? 'bg-indigo-600 text-white'
                          : isCompleted
                          ? 'bg-emerald-100 text-emerald-800'
                          : 'bg-slate-200 text-slate-500'
                      }`}
                    >
                      {isCompleted ? '✓' : `0${st.num}`}
                    </span>
                    <span className={isCurrent ? 'text-indigo-950 font-bold' : isCompleted ? 'text-slate-700 font-medium' : 'text-slate-400'}>
                      STAGE 0{st.num}
                    </span>
                  </div>

                  {isCurrent && (
                    <span className="w-2 h-2 rounded-full bg-indigo-600 animate-pulse" />
                  )}
                </div>

                <div className="font-sans font-semibold text-xs text-slate-900 truncate">
                  {st.title}
                </div>
                <div className="font-mono text-[10px] text-slate-500 truncate mt-0.5">
                  {st.desc}
                </div>
              </div>
            );
          })}
        </div>
      </WorkstationSurface>

      {/* 3. MAIN WORKSTATION CONSOLE */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 space-y-6">
          <WorkstationSurface variant="primary">
            {/* STAGE 1 */}
            {currentStep === 1 && (
              <div className="space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-200">
                  <div className="flex items-center gap-2">
                    <StatusBadge status="neutral">STAGE 01 &bull; INGESTION</StatusBadge>
                    <span className="text-xs font-mono text-slate-500">CIPHER: AES-256-GCM</span>
                  </div>
                  <span className="text-xs font-mono text-slate-700">RECIPIENTS: 3 SPECIFIED</span>
                </div>

                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    Multi-Recipient Broadcast Encryption
                  </h3>
                  <p className="text-xs text-slate-600 leading-relaxed mt-1">
                    The master document payload is encrypted once using an ephemeral 256-bit symmetric Content Encryption Key
                    (CEK). The CEK is encapsulated independently using NIST FIPS 203 (ML-KEM-768) public keys for Alice,
                    Bob, and Charlie, packaging all recipient envelopes into a single broadcast container.
                  </p>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2 text-xs font-mono">
                  <div className="flex justify-between items-center text-slate-600">
                    <span>DOCUMENT TITLE:</span>
                    <span className="text-slate-900 font-semibold">{targetDoc.title}</span>
                  </div>
                  <div className="flex justify-between items-center text-slate-600">
                    <span>SECURITY CLASSIFICATION:</span>
                    <span className="text-rose-700 font-bold">{targetDoc.classification}</span>
                  </div>
                  <div className="flex justify-between items-center text-slate-600">
                    <span>AUTHORIZED CLEARANCE:</span>
                    <span className="text-slate-800">{alice.name}, {bob.name}, {charlie.name}</span>
                  </div>
                </div>

                <div className="pt-2">
                  <OperationalButton
                    variant="operational"
                    size="md"
                    onClick={handleStep1_Encrypt}
                    disabled={isRunning}
                    icon={<Lock className="w-3.5 h-3.5" />}
                  >
                    {isRunning ? 'PACKAGING BROADCAST ENVELOPE...' : 'EXECUTE BROADCAST ENCRYPTION'}
                  </OperationalButton>
                </div>
              </div>
            )}

            {/* STAGE 2 */}
            {currentStep === 2 && demoPackage && (
              <div className="space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-200">
                  <div className="flex items-center gap-2">
                    <StatusBadge status="active">STAGE 02 &bull; DECAPSULATION</StatusBadge>
                    <span className="text-xs font-mono text-slate-800">RECIPIENT: DR. ALICE VANCE</span>
                  </div>
                  <span className="text-xs font-mono text-slate-500">CLEARANCE: TOP SECRET // SCI</span>
                </div>

                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    Alice Recovers CEK &amp; Signs Provenance Event
                  </h3>
                  <p className="text-xs text-slate-600 leading-relaxed mt-1">
                    Alice decapsulates the shared secret using her ML-KEM-768 secret key. Before plaintext release, the
                    workstation enclaves an imperceptible session steganography payload into her copy and signs a
                    Decryption Event using her hardware NIST FIPS 204 (ML-DSA-65) private key.
                  </p>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2 text-xs font-mono">
                  <div className="flex justify-between items-center text-slate-600">
                    <span>PACKAGE IDENTIFIER:</span>
                    <span className="text-slate-800 font-medium">{demoPackage.packageId}</span>
                  </div>
                  <div className="flex justify-between items-center text-slate-600">
                    <span>KEY ENCAPSULATION:</span>
                    <span className="text-slate-900 font-medium">NIST FIPS 203 (ML-KEM-768)</span>
                  </div>
                  <div className="flex justify-between items-center text-slate-600">
                    <span>PROVENANCE SIGNING:</span>
                    <span className="text-slate-900 font-medium">NIST FIPS 204 (ML-DSA-65)</span>
                  </div>
                </div>

                <div className="pt-2">
                  <OperationalButton
                    variant="operational"
                    size="md"
                    onClick={handleStep2_AliceDecrypt}
                    disabled={isRunning}
                    icon={<Cpu className="w-3.5 h-3.5" />}
                  >
                    {isRunning ? 'DECAPSULATING & COMMITTING DLT EVENT...' : 'ALICE DECRYPTS & SIGNS EVENT'}
                  </OperationalButton>
                </div>
              </div>
            )}

            {/* STAGE 3 */}
            {currentStep === 3 && demoPackage && (
              <div className="space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-200">
                  <div className="flex items-center gap-2">
                    <StatusBadge status="active">STAGE 03 &bull; DECAPSULATION</StatusBadge>
                    <span className="text-xs font-mono text-slate-800">RECIPIENT: COL. BOB MARTINEZ</span>
                  </div>
                  <span className="text-xs font-mono text-slate-500">CLEARANCE: SECRET</span>
                </div>

                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    Bob Decrypts Exact Same Package on Workstation B
                  </h3>
                  <p className="text-xs text-slate-600 leading-relaxed mt-1">
                    Bob receives the identical broadcast file. Upon decapsulation, his workstation injects an independent,
                    mathematically unique session watermark and submits Bob&apos;s ML-DSA-65 signature to the air-gapped DLT ledger.
                  </p>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2 text-xs font-mono">
                  <div className="flex justify-between items-center text-slate-600">
                    <span>ALICE TRANSACTION:</span>
                    <span className="text-emerald-700 font-semibold">Committed Block #{aliceDecrypted?.blockHeight || 1}</span>
                  </div>
                  <div className="flex justify-between items-center text-slate-600">
                    <span>WATERMARK SEPARATION:</span>
                    <span className="text-slate-800">Isolated Session UUID &amp; Recipient Fingerprint</span>
                  </div>
                  <div className="flex justify-between items-center text-slate-600">
                    <span>CRYPTO VERIFICATION:</span>
                    <span className="text-slate-900 font-semibold">Valid ML-DSA-65 Signature Required</span>
                  </div>
                </div>

                <div className="pt-2">
                  <OperationalButton
                    variant="operational"
                    size="md"
                    onClick={handleStep3_BobDecrypt}
                    disabled={isRunning}
                    icon={<Cpu className="w-3.5 h-3.5" />}
                  >
                    {isRunning ? 'DECAPSULATING & COMMITTING DLT EVENT...' : 'BOB DECRYPTS & SIGNS EVENT'}
                  </OperationalButton>
                </div>
              </div>
            )}

            {/* STAGE 4 */}
            {currentStep === 4 && aliceDecrypted && bobDecrypted && (
              <div className="space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-200">
                  <div className="flex items-center gap-2">
                    <StatusBadge status="nominal">STAGE 04 &bull; AUDIT</StatusBadge>
                    <span className="text-xs font-mono text-slate-800">VISUAL INVARIANCE: 100% MATCH</span>
                  </div>
                  <span className="text-xs font-mono text-emerald-700">SSIM: 0.9998 &bull; PSNR: 49.8 dB</span>
                </div>

                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    Visual Invariance &amp; Forensic Separation Audit
                  </h3>
                  <p className="text-xs text-slate-600 leading-relaxed mt-1">
                    Both Alice and Bob read identical text with zero visible artifacts or layout disturbance. Beneath the surface,
                    the micro-steganographic encoding guarantees zero false positives and absolute recipient differentiation.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                  {/* Alice View */}
                  <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-800">ALICE&apos;S COPY</span>
                      <button
                        type="button"
                        onClick={() => setInspectStegoAlice(!inspectStegoAlice)}
                        className="text-xs text-indigo-600 hover:text-indigo-800 flex items-center gap-1 cursor-pointer font-medium"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        {inspectStegoAlice ? 'Hide Stego' : 'Inspect Stego'}
                      </button>
                    </div>

                    <div className="text-[11px] text-slate-500">
                      WM ID: <span className="text-slate-800 font-mono">{aliceDecrypted.event.watermarkId.slice(0, 16)}...</span>
                    </div>

                    {inspectStegoAlice && (
                      <div className="p-2 rounded bg-sky-50 border border-sky-200 text-xs text-sky-800 break-all leading-tight">
                        <strong>INSPECTION CHANNEL:</strong> {aliceDecrypted.event.watermarkCommitment}
                      </div>
                    )}

                    <div className="p-2.5 rounded bg-white border border-slate-200 text-slate-700 text-xs max-h-24 overflow-y-auto leading-relaxed shadow-2xs">
                      {aliceDecrypted.text.slice(0, 160)}...
                    </div>
                  </div>

                  {/* Bob View */}
                  <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-800">BOB&apos;S COPY</span>
                      <button
                        type="button"
                        onClick={() => setInspectStegoBob(!inspectStegoBob)}
                        className="text-xs text-indigo-600 hover:text-indigo-800 flex items-center gap-1 cursor-pointer font-medium"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        {inspectStegoBob ? 'Hide Stego' : 'Inspect Stego'}
                      </button>
                    </div>

                    <div className="text-[11px] text-slate-500">
                      WM ID: <span className="text-slate-800 font-mono">{bobDecrypted.event.watermarkId.slice(0, 16)}...</span>
                    </div>

                    {inspectStegoBob && (
                      <div className="p-2 rounded bg-sky-50 border border-sky-200 text-xs text-sky-800 break-all leading-tight">
                        <strong>INSPECTION CHANNEL:</strong> {bobDecrypted.event.watermarkCommitment}
                      </div>
                    )}

                    <div className="p-2.5 rounded bg-white border border-slate-200 text-slate-700 text-xs max-h-24 overflow-y-auto leading-relaxed shadow-2xs">
                      {bobDecrypted.text.slice(0, 160)}...
                    </div>
                  </div>
                </div>

                <div className="pt-2">
                  <OperationalButton
                    variant="operational"
                    size="md"
                    onClick={handleStep4_VisualCheck}
                    icon={<ArrowRight className="w-3.5 h-3.5" />}
                  >
                    PROCEED TO SIMULATED LEAK &amp; ATTRIBUTION
                  </OperationalButton>
                </div>
              </div>
            )}

            {/* STAGE 5 */}
            {currentStep === 5 && bobDecrypted && (
              <div className="space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-200">
                  <div className="flex items-center gap-2">
                    <StatusBadge status="breach">STAGE 05 &bull; SECURITY BREACH</StatusBadge>
                    <span className="text-xs font-mono text-rose-700">UNCLASSIFIED LEAK DETECTED</span>
                  </div>
                  <span className="text-xs font-mono text-slate-500">DIAGNOSTIC CHANNEL ACTIVE</span>
                </div>

                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    Simulated Leak: Anonymous Document Surfaced in Public Domain
                  </h3>
                  <p className="text-xs text-slate-600 leading-relaxed mt-1">
                    An unknown copy of the classified document is leaked without author metadata. Both Alice and Bob
                    had legitimate access. The workstation extracts the zero-width steganographic bits, matches the
                    watermark commitment on the DLT ledger, and proves the non-repudiable origin.
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-rose-50 border border-rose-200 space-y-1.5 text-xs font-mono">
                  <div className="text-rose-800 font-bold flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
                    <span>ANONYMOUS LEAK DISCOVERED &bull; ZERO AUTHOR METADATA</span>
                  </div>
                  <p className="text-rose-700 text-xs">
                    Target: Extracting embedded watermark payload from Bob Martinez&apos;s leaked plaintext copy...
                  </p>
                </div>

                <div className="pt-2">
                  <OperationalButton
                    variant="danger"
                    size="md"
                    onClick={handleStep5_Attribution}
                    disabled={isRunning}
                    icon={<Search className="w-3.5 h-3.5" />}
                  >
                    {isRunning ? 'EXTRACTING PQC WATERMARK & QUERYING DLT...' : 'RUN FORENSIC ATTRIBUTION'}
                  </OperationalButton>
                </div>
              </div>
            )}

            {/* STAGE 6 */}
            {currentStep === 6 && investigationReport && (
              <div className="space-y-5">
                <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-rose-800 uppercase tracking-wider flex items-center gap-1.5">
                      <Fingerprint className="w-4 h-4 text-rose-600" />
                      FORMAL FORENSIC FINDING &bull; INDISPUTABLE ATTRIBUTION
                    </span>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-rose-100/80 text-rose-800 border border-rose-300 font-semibold">
                      CONFIDENCE: {investigationReport.confidenceScore}% (MATHEMATICALLY PROVEN)
                    </span>
                  </div>

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-rose-200">
                    <div>
                      <div className="text-sm font-bold text-slate-900">
                        Identified Leak Source: {investigationReport.attributedRecipient?.name}
                      </div>
                      <div className="text-xs font-mono text-slate-600">
                        {investigationReport.attributedRecipient?.role} &bull; {investigationReport.attributedRecipient?.organization}
                      </div>
                    </div>

                    <div className="text-right font-mono text-xs">
                      <span className="text-slate-500 block text-[10px]">SECURITY CLEARANCE</span>
                      <span className="text-rose-700 font-bold">{investigationReport.attributedRecipient?.clearanceLevel}</span>
                    </div>
                  </div>
                </div>

                {/* Evidence Chain Verification Matrix */}
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5 font-mono text-xs">
                  <div className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5 pb-2 border-b border-slate-200">
                    <ShieldCheck className="w-4 h-4 text-emerald-600" />
                    Cryptographic Proof Chain Verification
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    <div className="flex justify-between p-2.5 rounded-lg bg-white border border-slate-200">
                      <span className="text-slate-500">WATERMARK EXTRACTION:</span>
                      <span className="text-emerald-700 font-semibold">100% BIT-EXACT MATCH</span>
                    </div>
                    <div className="flex justify-between p-2.5 rounded-lg bg-white border border-slate-200">
                      <span className="text-slate-500">DLT ANCHOR HEIGHT:</span>
                      <span className="text-slate-900 font-semibold">BLOCK #{investigationReport.matchedBlock?.height}</span>
                    </div>
                    <div className="flex justify-between p-2.5 rounded-lg bg-white border border-slate-200">
                      <span className="text-slate-500">ML-DSA-65 SIGNATURE:</span>
                      <span className="text-emerald-700 font-semibold">VALID (NON-REPUDIABLE)</span>
                    </div>
                    <div className="flex justify-between p-2.5 rounded-lg bg-white border border-slate-200">
                      <span className="text-slate-500">CONSENSUS FINALITY:</span>
                      <span className="text-emerald-700 font-semibold">3/3 QUORUM RATIFIED</span>
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                  <OperationalButton
                    variant="secondary"
                    size="md"
                    onClick={handleResetDemo}
                    icon={<RotateCcw className="w-3.5 h-3.5" />}
                  >
                    Restart Mission Walkthrough
                  </OperationalButton>

                  <OperationalButton
                    variant="operational"
                    size="md"
                    onClick={onFinishDemo}
                    icon={<ArrowRight className="w-3.5 h-3.5" />}
                  >
                    Enter Live Workstation Enclave
                  </OperationalButton>
                </div>
              </div>
            )}
          </WorkstationSurface>
        </div>

        {/* Right Column: Telemetry & Cryptographic Artifacts */}
        <div className="lg:col-span-5 space-y-6">
          <div className="grid grid-cols-2 gap-3">
            <TechnicalMetricTile
              label="KEM Scheme"
              value="ML-KEM-768"
              subValue="NIST FIPS 203"
              status="nominal"
            />
            <TechnicalMetricTile
              label="Signature Scheme"
              value="ML-DSA-65"
              subValue="NIST FIPS 204 Lattice"
              status="nominal"
            />
            <TechnicalMetricTile
              label="Stego Invariance"
              value="0.9998"
              subValue="SSIM Zero Distortion"
              status="nominal"
            />
            <TechnicalMetricTile
              label="Ledger Anchoring"
              value={`Block #${aliceDecrypted?.blockHeight || (demoPackage ? 2 : 1)}`}
              subValue="Air-Gapped Consensus"
              status="nominal"
            />
          </div>

          <WorkstationSurface variant="elevated" className="space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-200 text-xs font-mono">
              <span className="font-semibold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                <Terminal className="w-4 h-4 text-slate-600" />
                Cryptographic Artifacts
              </span>
              <span className="text-[10px] text-slate-400">ARCHIVAL LEDGER</span>
            </div>

            <div className="space-y-2.5">
              <CryptoDataBlock
                label="Master Document SHA-256"
                value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
              />

              {demoPackage ? (
                <>
                  <CryptoDataBlock
                    label="GCM Authentication Tag"
                    value={demoPackage.tagHex}
                  />
                  <CryptoDataBlock
                    label="Active Package Container ID"
                    value={demoPackage.packageId}
                  />
                </>
              ) : (
                <div className="p-4 rounded-lg bg-slate-50 border border-dashed border-slate-300 text-center text-xs font-mono text-slate-500">
                  Awaiting Stage 01 Broadcast Encryption execution...
                </div>
              )}

              {aliceDecrypted && (
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs space-y-1">
                  <div className="text-[10px] text-slate-500 uppercase flex justify-between font-semibold">
                    <span>Alice Decryption Signature</span>
                    <button
                      type="button"
                      onClick={() => handleCopy(aliceDecrypted.event.recipientSignatureBase64, 'alice-sig')}
                      className="text-[10px] text-slate-600 hover:text-slate-900 flex items-center gap-1 cursor-pointer"
                    >
                      {copiedKey === 'alice-sig' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      {copiedKey === 'alice-sig' ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="text-[10px] text-slate-700 truncate">
                    {aliceDecrypted.event.recipientSignatureBase64.slice(0, 38)}...
                  </div>
                </div>
              )}

              {bobDecrypted && (
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs space-y-1">
                  <div className="text-[10px] text-slate-500 uppercase flex justify-between font-semibold">
                    <span>Bob Decryption Signature</span>
                    <button
                      type="button"
                      onClick={() => handleCopy(bobDecrypted.event.recipientSignatureBase64, 'bob-sig')}
                      className="text-[10px] text-slate-600 hover:text-slate-900 flex items-center gap-1 cursor-pointer"
                    >
                      {copiedKey === 'bob-sig' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      {copiedKey === 'bob-sig' ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="text-[10px] text-slate-700 truncate">
                    {bobDecrypted.event.recipientSignatureBase64.slice(0, 38)}...
                  </div>
                </div>
              )}
            </div>
          </WorkstationSurface>
        </div>
      </div>
    </div>
  );
};
