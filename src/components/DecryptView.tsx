import React, { useState, useEffect } from 'react';
import {
  Unlock,
  Key,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Eye,
  Download,
  FileText,
  FileCheck,
  ArrowRight,
  ChevronDown,
  Layers,
  Sparkles,
  Lock,
  Bell,
} from 'lucide-react';
import {
  PageShell,
  PageHeader,
  Section,
  PrimaryButton,
  SecondaryButton,
  DangerButton,
  StatusBadge,
  VerificationBadge,
  KeyValueRow,
  TechnicalDetails,
  EmptyState,
} from './ui/designSystem';
import { Recipient, EncryptedPackage, DecryptionEvent, WatermarkPayload } from '../types';
import { DistributionService } from '../services/distributionService';
import { sessionManager, AuthenticatedSession } from '../crypto/sessionManager';
import { SihpkgImportSection } from './SihpkgImportSection';
import { airGappedStorage } from '../storage/airGappedStorage';
import { AssignmentService } from '../services/assignmentService';
import { ReceiptService } from '../services/receiptService';
import { RecipientInboxDrawer } from './RecipientInboxDrawer';
import { ReceiptVerificationModal } from './ReceiptVerificationModal';

interface DecryptViewProps {
  recipients: Recipient[];
  activePackage: EncryptedPackage | null;
  onPackageImported?: (pkg: EncryptedPackage) => void;
  onDecryptionSuccess: (result: {
    recipient: Recipient;
    watermarkedText: string;
    decryptionEvent: DecryptionEvent;
    watermarkPayload: WatermarkPayload;
    blockHeight: number;
  }) => void;
  onSimulateLeak: (
    leakedText: string,
    metadata: { title: string; recipientName: string },
    pdfBytes?: Uint8Array,
    fileName?: string
  ) => void;
  onNavigateToForensics: () => void;
  onNavigateToLedger: () => void;
}

export const DecryptView: React.FC<DecryptViewProps> = ({
  recipients,
  activePackage,
  onPackageImported,
  onDecryptionSuccess,
  onSimulateLeak,
  onNavigateToForensics,
  onNavigateToLedger,
}) => {
  const [currentPackage, setCurrentPackage] = useState<EncryptedPackage | null>(activePackage);

  useEffect(() => {
    if (activePackage) {
      setCurrentPackage(activePackage);
    }
  }, [activePackage]);

  const handlePackageImported = (pkg: EncryptedPackage) => {
    setCurrentPackage(pkg);
    if (onPackageImported) {
      onPackageImported(pkg);
    }
  };

  // Session State directly driven by sessionManager
  const [activeSession, setActiveSession] = useState<AuthenticatedSession | null>(() =>
    sessionManager.getActiveSession()
  );

  // Unlock credentials state for when locked
  const [selectedUserId, setSelectedUserId] = useState<string>(recipients[0]?.id || '');
  const [passphrase, setPassphrase] = useState<string>('');
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [isUnlocking, setIsUnlocking] = useState(false);

  // Decryption execution state
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptedResult, setDecryptedResult] = useState<{
    watermarkedText: string;
    decryptedBytes?: Uint8Array;
    isPdf?: boolean;
    mimeType?: string;
    filename?: string;
    decryptionEvent: DecryptionEvent;
    watermarkPayload: WatermarkPayload;
    blockHeight: number;
  } | null>(null);

  const [activeStep, setActiveStep] = useState<number>(0);
  const [showStegoChannel, setShowStegoChannel] = useState(false);

  // Recipient Inbox & Signed Offline Receipt (.sihrcpt) State
  const [isInboxOpen, setIsInboxOpen] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isVerifyModalOpen, setIsVerifyModalOpen] = useState(false);
  const [isDownloadingReceipt, setIsDownloadingReceipt] = useState(false);
  const [receiptNotice, setReceiptNotice] = useState<string | null>(null);
  const [receiptError, setReceiptError] = useState<string | null>(null);

  // Subscribe to sessionManager updates
  useEffect(() => {
    const unsubscribe = sessionManager.subscribe((session) => {
      setActiveSession(session);
      if (!session) {
        setDecryptedResult(null);
        setUnreadCount(0);
      }
    });
    return unsubscribe;
  }, []);

  // Update unread count whenever activeSession changes
  useEffect(() => {
    if (activeSession && activeSession.status === 'ACTIVE') {
      AssignmentService.getNotificationsForRecipient(activeSession.userId, activeSession)
        .then((notifs) => {
          setUnreadCount(notifs.filter((n) => !n.read).length);
        })
        .catch(() => setUnreadCount(0));
    } else {
      setUnreadCount(0);
    }
  }, [activeSession]);

  const handleSelectPackageFromInbox = async (packageId: string) => {
    try {
      const stored = await airGappedStorage.getPackage(packageId);
      if (stored) {
        setCurrentPackage(stored);
        if (onPackageImported) {
          onPackageImported(stored);
        }
        setDecryptedResult(null);
      }
    } catch (err) {
      console.warn('[DecryptView] Failed to load package from inbox:', err);
    }
  };

  const handleDownloadReceipt = async () => {
    if (!decryptedResult || !currentPackage || !currentRecipient || !activeSession) return;
    setIsDownloadingReceipt(true);
    setReceiptNotice(null);
    try {
      const assignments = await AssignmentService.getAssignmentsForRecipient(currentRecipient.id, activeSession);
      const assignment = assignments.find((a) => a.packageId === currentPackage.packageId);

      const receipt = await ReceiptService.generateReceipt({
        pkg: currentPackage,
        recipient: currentRecipient,
        decryptionEvent: decryptedResult.decryptionEvent,
        watermarkPayload: decryptedResult.watermarkPayload,
        blockHeight: decryptedResult.blockHeight,
        assignment,
        session: activeSession,
      });

      ReceiptService.triggerReceiptDownload(receipt);
      setReceiptNotice(`Downloaded verified offline receipt (${receipt.receiptId})`);
      setTimeout(() => setReceiptNotice(null), 5000);
    } catch (err: any) {
      console.error('[DecryptView] Receipt download failed:', err);
      setReceiptError(`Receipt generation failed: ${err.message}`);
      setTimeout(() => setReceiptError(null), 6000);
    } finally {
      setIsDownloadingReceipt(false);
    }
  };

  const currentRecipient = recipients.find((r) => r.id === activeSession?.userId) || null;

  // Authorization: Does the active package contain an ML-KEM envelope for the authenticated recipient?
  const hasEnvelope = currentPackage?.envelopes.some(
    (e) => e.recipientId === activeSession?.userId
  );

  const handleUnlockKeystore = async (e: React.FormEvent) => {
    e.preventDefault();
    setUnlockError(null);
    const targetRecipient = recipients.find((r) => r.id === selectedUserId);
    if (!targetRecipient) {
      setUnlockError('Please select a local identity to unlock.');
      return;
    }

    setIsUnlocking(true);
    try {
      await sessionManager.createSession(targetRecipient, passphrase);
      setPassphrase('');
      setUnlockError(null);
    } catch (err: any) {
      setUnlockError('Authentication failed: Incorrect passphrase or corrupted keystore.');
    } finally {
      setIsUnlocking(false);
    }
  };

  const handleLockSession = () => {
    sessionManager.lockSession();
    setDecryptedResult(null);
  };

  const handleExecuteDecryption = async () => {
    if (!currentPackage || !currentRecipient || !hasEnvelope) return;

    setIsDecrypting(true);
    setActiveStep(1);

    try {
      // Simulate sequential visual steps for comprehension
      await new Promise((r) => setTimeout(r, 200));
      setActiveStep(2);
      await new Promise((r) => setTimeout(r, 200));
      setActiveStep(3);
      await new Promise((r) => setTimeout(r, 200));
      setActiveStep(4);

      const result = await DistributionService.executeRecipientDecryption(
        currentPackage,
        currentRecipient,
        activeSession
      );

      setDecryptedResult(result);
      onDecryptionSuccess({
        recipient: currentRecipient,
        watermarkedText: result.watermarkedText,
        decryptionEvent: result.decryptionEvent,
        watermarkPayload: result.watermarkPayload,
        blockHeight: result.blockHeight,
      });
    } catch (err: any) {
      console.error('Decryption failed:', err);
    } finally {
      setIsDecrypting(false);
    }
  };

  const handleTriggerLeak = () => {
    if (!decryptedResult || !currentPackage || !currentRecipient) return;
    const baseTitle = currentPackage.documentTitle.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_-]/g, '');
    const isPdf = decryptedResult.isPdf || currentPackage.isPdf || false;
    const fileName = `${baseTitle}_Leaked_${currentRecipient.avatarInitials}.${isPdf ? 'pdf' : 'txt'}`;

    onSimulateLeak(
      decryptedResult.watermarkedText,
      {
        title: currentPackage.documentTitle,
        recipientName: currentRecipient.name,
      },
      decryptedResult.decryptedBytes,
      fileName
    );
    onNavigateToForensics();
  };

  const handleDownloadCopy = () => {
    if (!decryptedResult || !currentPackage || !currentRecipient) return;

    const isPdf = decryptedResult.isPdf || currentPackage.isPdf || false;
    let blob: Blob;
    let ext = 'txt';

    if (isPdf && decryptedResult.decryptedBytes) {
      // Ensure binary PDF bytes are downloaded with application/pdf MIME type
      // Make sure a fresh ArrayBuffer copy is passed to Blob
      const binaryCopy = new Uint8Array(decryptedResult.decryptedBytes).slice();
      blob = new Blob([binaryCopy], { type: 'application/pdf' });
      ext = 'pdf';
    } else {
      blob = new Blob([decryptedResult.watermarkedText], { type: 'text/plain;charset=utf-8' });
      ext = 'txt';
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const baseTitle = currentPackage.documentTitle.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_-]/g, '');
    a.download = `${baseTitle}_Decrypted_${currentRecipient.avatarInitials}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <PageShell>
      <PageHeader
        title="Decrypt document"
        description="Decrypt locally and create a signed provenance record."
        badge={
          activeSession ? (
            <StatusBadge status="verified" icon={<CheckCircle2 className="w-3 h-3 text-emerald-600" />}>
              Session active ({activeSession.userName})
            </StatusBadge>
          ) : (
            <StatusBadge status="neutral" icon={<Lock className="w-3 h-3 text-slate-500" />}>
              Keystore locked
            </StatusBadge>
          )
        }
        action={
          <div className="flex items-center gap-2">
            <SecondaryButton
              size="sm"
              icon={<FileCheck className="w-3.5 h-3.5 text-indigo-600" />}
              onClick={() => setIsVerifyModalOpen(true)}
            >
              Verify receipt (.sihrcpt)
            </SecondaryButton>
            {activeSession && (
              <SecondaryButton
                size="sm"
                icon={<Bell className="w-3.5 h-3.5 text-indigo-600" />}
                onClick={() => setIsInboxOpen(true)}
              >
                Inbox
                {unreadCount > 0 && (
                  <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-indigo-600 text-white tabular-nums">
                    {unreadCount}
                  </span>
                )}
              </SecondaryButton>
            )}
          </div>
        }
      />

      {/* 1. AUTHENTICATED SESSION VS LOCKED KEYSTORE STATE */}
      {!activeSession ? (
        <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Unlock Local Keystore</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Authentication required. Enter your secret passphrase to decrypt your ML-KEM and ML-DSA private keys into ephemeral memory.
              </p>
            </div>
            <div className="p-2 bg-indigo-50 border border-indigo-100 rounded-lg text-indigo-700">
              <Key className="w-4 h-4" />
            </div>
          </div>

          <form onSubmit={handleUnlockKeystore} className="grid grid-cols-1 sm:grid-cols-12 gap-3 items-end pt-1">
            <div className="sm:col-span-4">
              <label className="block text-slate-700 font-medium text-xs mb-1">Select local personnel account</label>
              <select
                value={selectedUserId}
                onChange={(e) => {
                  setSelectedUserId(e.target.value);
                  setUnlockError(null);
                }}
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
              >
                {recipients.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name} ({r.role})
                  </option>
                ))}
              </select>
            </div>

            <div className="sm:col-span-5">
              <label className="block text-slate-700 font-medium text-xs mb-1">Passphrase</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => {
                  setPassphrase(e.target.value);
                  setUnlockError(null);
                }}
                placeholder="Enter passphrase (e.g. AliceVance2026!)"
                required
                className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
              />
            </div>

            <div className="sm:col-span-3">
              <PrimaryButton size="md" type="submit" loading={isUnlocking} className="w-full">
                Unlock Keystore
              </PrimaryButton>
            </div>
          </form>

          {unlockError && (
            <div className="p-2.5 rounded-lg bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{unlockError}</span>
            </div>
          )}

          <div className="p-3 bg-slate-50/70 border border-slate-200/80 rounded-lg text-[11px] text-slate-500 space-y-1">
            <strong className="text-slate-700">Demo Passphrases:</strong>
            <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] text-slate-600 pt-0.5">
              <span>Dr. Alice: <strong className="text-slate-800">AliceVance2026!</strong></span>
              <span>Col. Bob: <strong className="text-slate-800">BobMartinez2026!</strong></span>
              <span>Cmdr. Charlie: <strong className="text-slate-800">CharlieChen2026!</strong></span>
              <span>Amb. Diana: <strong className="text-slate-800">DianaRoss2026!</strong></span>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-slate-50 border border-slate-200/90 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full bg-white border border-slate-200 flex items-center justify-center font-bold text-slate-800 shrink-0">
              {activeSession.avatarInitials}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 font-normal">Active Session:</span>
                <strong className="text-slate-900 font-semibold">{activeSession.userName}</strong>
                <span className="text-[10px] text-slate-400">({activeSession.userRole})</span>
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">
                Session ID: <span className="font-mono text-slate-700">{activeSession.sessionId.slice(0, 8)}...</span> &bull; 
                Clearance: {activeSession.userClearance} &bull; 
                Key FP: <span className="font-mono text-slate-700">{activeSession.keyFingerprint}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 self-end sm:self-center">
            <SecondaryButton
              size="sm"
              icon={<Bell className="w-3.5 h-3.5 text-indigo-600" />}
              onClick={() => setIsInboxOpen(true)}
            >
              Inbox
              {unreadCount > 0 && (
                <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-indigo-600 text-white tabular-nums">
                  {unreadCount}
                </span>
              )}
            </SecondaryButton>
            <SecondaryButton size="sm" icon={<Lock className="w-3 h-3 text-slate-500" />} onClick={handleLockSession}>
              Lock session
            </SecondaryButton>
          </div>
        </div>
      )}

      {/* 2. SECURE PORTABLE PACKAGE (.sihpkg) INGESTION & UNTRUSTED TRANSPORT */}
      <SihpkgImportSection
        recipients={recipients}
        activeSession={activeSession}
        onPackageImported={handlePackageImported}
        currentPackage={currentPackage}
      />

      {/* 3. DOCUMENT READY STATUS & PRE-DECRYPTION CHECKLIST */}
      {currentPackage ? (
        <Section
          title="Document ready for decryption"
          description={currentPackage.documentTitle}
          action={
            !activeSession ? (
              <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-amber-50 text-amber-800 border border-amber-200">
                Authentication required
              </span>
            ) : hasEnvelope ? (
              <VerificationBadge label="Decryption authorized" />
            ) : (
              <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-rose-50 text-rose-700 border border-rose-200">
                Not authorized for {activeSession.userName}
              </span>
            )
          }
        >
          <div className="space-y-4 pt-1">
            {/* Document metadata line */}
            <div className="p-3 bg-slate-50 rounded-lg border border-slate-200/80 flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="space-y-0.5">
                <span className="text-slate-500 text-[11px]">Classification:</span>
                <div className="font-semibold text-slate-900">{currentPackage.classification}</div>
              </div>
              <div className="space-y-0.5">
                <span className="text-slate-500 text-[11px]">Envelopes in package:</span>
                <div className="font-semibold text-slate-900">{currentPackage.envelopes.length} Recipients</div>
              </div>
              <div className="space-y-0.5">
                <span className="text-slate-500 text-[11px]">Sender:</span>
                <div className="font-semibold text-slate-900">{currentPackage.senderName}</div>
              </div>
            </div>

            {/* Before you continue checklist */}
            <div className="p-3.5 bg-slate-50/70 rounded-xl border border-slate-200/80 space-y-2">
              <span className="text-xs font-semibold text-slate-900 block">
                Security assertions:
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-600">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  <span>Decrypted in local security environment</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  <span>Unique forensic fingerprint created</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  <span>Decryption event digitally signed (ML-DSA-65)</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  <span>Provenance recorded in tamper-evident ledger</span>
                </div>
              </div>
            </div>

            {/* Decrypt Action Button */}
            {!decryptedResult && (
              <div className="pt-2 flex justify-end">
                <PrimaryButton
                  size="lg"
                  icon={<Unlock className="w-4 h-4" />}
                  onClick={handleExecuteDecryption}
                  loading={isDecrypting}
                  disabled={!activeSession || !hasEnvelope}
                  data-tour-target="decrypt-recipient-btn"
                >
                  {!activeSession
                    ? 'Unlock keystore to decrypt'
                    : !hasEnvelope
                    ? 'Unauthorized (No Envelope)'
                    : isDecrypting
                    ? 'Executing decryption pipeline...'
                    : 'Execute authenticated decryption'}
                </PrimaryButton>
              </div>
            )}

            {/* Live Progress indicator during decryption */}
            {isDecrypting && (
              <div className="p-3 bg-indigo-50/60 rounded-lg border border-indigo-100 text-xs text-indigo-900 space-y-1">
                <div className="font-semibold flex items-center gap-2">
                  <div className="w-3 h-3 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin" />
                  <span>Decrypting document...</span>
                </div>
                <div className="text-[11px] text-slate-600 font-mono">
                  {activeStep === 1 && '1/4 Recovering key via ML-KEM-768 decapsulation...'}
                  {activeStep === 2 && '2/4 Decrypting AES-256-GCM ciphertext in memory...'}
                  {activeStep === 3 && '3/4 Embedding invisible forensic fingerprint...'}
                  {activeStep === 4 && '4/4 Signing decryption event with ML-DSA-65 & committing to ledger...'}
                </div>
              </div>
            )}

            {/* 3. POST-DECRYPTION SUCCESS VIEWPORT */}
            {decryptedResult && (
              <div className="space-y-4 pt-4 border-t border-slate-100 animate-in fade-in duration-150">
                {/* Completion summary banner */}
                <div className="p-4 bg-emerald-50/70 border border-emerald-200/90 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                  <div>
                    <div className="font-semibold text-emerald-900 flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                      Decryption complete &bull; Provenance recorded
                    </div>
                    <div className="text-emerald-800 text-[11px] mt-0.5">
                      Forensic fingerprint: <span className="font-mono font-semibold">{decryptedResult.watermarkPayload.watermarkId}</span> &bull; Ledger: <span className="font-mono">Block #{decryptedResult.blockHeight}</span>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <SecondaryButton
                      size="sm"
                      icon={<Eye className="w-3.5 h-3.5 text-slate-500" />}
                      onClick={() => setShowStegoChannel(!showStegoChannel)}
                    >
                      {showStegoChannel ? 'Hide watermark' : 'Inspect watermark'}
                    </SecondaryButton>

                    <SecondaryButton
                      size="sm"
                      icon={<Download className="w-3.5 h-3.5 text-slate-500" />}
                      onClick={handleDownloadCopy}
                    >
                      Download copy
                    </SecondaryButton>

                    <SecondaryButton
                      size="sm"
                      icon={<FileCheck className="w-3.5 h-3.5 text-indigo-600" />}
                      loading={isDownloadingReceipt}
                      onClick={handleDownloadReceipt}
                      title="Download verifiable .sihrcpt receipt with ML-DSA-65 post-quantum signature"
                    >
                      Download signed receipt (.sihrcpt)
                    </SecondaryButton>
                  </div>
                </div>

                {receiptNotice && (
                  <div className="p-3 rounded-xl bg-emerald-50/90 border border-emerald-200 text-xs text-emerald-900 flex items-center justify-between animate-in fade-in">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                      <span>{receiptNotice}</span>
                    </div>
                    <button
                      onClick={() => setIsVerifyModalOpen(true)}
                      className="text-xs font-semibold text-emerald-700 hover:text-emerald-900 underline cursor-pointer"
                    >
                      Verify receipt offline
                    </button>
                  </div>
                )}

                {receiptError && (
                  <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-center gap-2 animate-in fade-in">
                    <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
                    <span>{receiptError}</span>
                  </div>
                )}

                {/* Inspect Stego Channel Accordion Box */}
                {showStegoChannel && (
                  <div className="p-3 bg-sky-50/80 border border-sky-200 rounded-lg text-xs space-y-1.5 font-mono text-sky-950">
                    <div className="font-semibold flex items-center justify-between">
                      <span>STEGANOGRAPHIC WATERMARK DETAILS</span>
                      <span className="text-[10px] text-sky-700 bg-white px-2 py-0.5 rounded border border-sky-200">
                        DIAGNOSTIC VIEW
                      </span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] pt-1">
                      <div>Session UUID: {decryptedResult.watermarkPayload.sessionId}</div>
                      <div>Watermark ID: {decryptedResult.watermarkPayload.watermarkId}</div>
                      <div>Fingerprint: {decryptedResult.watermarkPayload.recipientFingerprint}</div>
                      <div>Timestamp: {new Date(decryptedResult.watermarkPayload.timestamp).toLocaleTimeString()}</div>
                    </div>
                    <p className="text-[11px] text-sky-800 pt-1 font-sans">
                      The document displayed below is visually 100% normal. {decryptedResult.isPdf ? 'The watermark is embedded into the PDF structural catalog enclave (/ForensicProvenance) and imperceptible page stream operators.' : 'The watermark is encoded steganographically using zero-width Unicode characters.'}
                    </p>
                  </div>
                )}

                {/* Decrypted Document Text Viewport */}
                <div className="p-5 bg-white border border-slate-200 rounded-xl text-xs font-mono leading-relaxed max-h-96 overflow-y-auto whitespace-pre-wrap select-text shadow-2xs">
                  {decryptedResult.watermarkedText}
                </div>

                {/* Actions Bar & Leak Simulation Trigger */}
                <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
                  <span className="text-[11px] text-slate-500">
                    Document bound to {currentRecipient?.name || 'Authorized Recipient'}&apos;s verified identity.
                  </span>

                  <div className="flex items-center gap-2">
                    <DangerButton
                      size="sm"
                      icon={<AlertTriangle className="w-3.5 h-3.5" />}
                      onClick={handleTriggerLeak}
                      data-tour-target="simulate-leak-btn"
                    >
                      Simulate anonymous leak of {currentRecipient?.name || 'recipient'}&apos;s copy
                    </DangerButton>
                  </div>
                </div>

                {/* Technical details disclosure */}
                <TechnicalDetails title="Signed decryption receipt &amp; ledger proof">
                  <KeyValueRow label="Event ID" value={decryptedResult.decryptionEvent.eventId} />
                  <KeyValueRow label="Watermark Commitment" value={decryptedResult.decryptionEvent.watermarkCommitment} copyable />
                  <KeyValueRow label="Recipient Signature (ML-DSA-65)" value={decryptedResult.decryptionEvent.recipientSignatureBase64.slice(0, 48) + '...'} copyable />
                  <KeyValueRow label="Committed Ledger Block" value={`Block #${decryptedResult.blockHeight}`} />
                  <div className="pt-2 text-[11px] text-slate-500">
                    This decryption event was ratified by all validator nodes and committed permanently to the local air-gapped ledger.
                  </div>
                </TechnicalDetails>
              </div>
            )}
          </div>
        </Section>
      ) : (
        <EmptyState
          icon={<FileText className="w-8 h-8" />}
          title="No distribution package ready"
          description="Go to Documents to select a document and encrypt it for authorized recipients."
          action={
            <SecondaryButton size="sm" onClick={onNavigateToForensics}>
              Go to Documents
            </SecondaryButton>
          }
        />
      )}

      {/* 4. RECIPIENT INBOX DRAWER */}
      <RecipientInboxDrawer
        isOpen={isInboxOpen}
        onClose={() => setIsInboxOpen(false)}
        activeSession={activeSession}
        onSelectPackage={handleSelectPackageFromInbox}
        onUnreadCountChange={setUnreadCount}
      />

      {/* 5. OFFLINE RECEIPT (.sihrcpt) VERIFICATION MODAL */}
      <ReceiptVerificationModal
        isOpen={isVerifyModalOpen}
        onClose={() => setIsVerifyModalOpen(false)}
      />
    </PageShell>
  );
};
