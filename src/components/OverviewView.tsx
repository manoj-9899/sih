import React from 'react';
import {
  ShieldCheck,
  FileText,
  Users,
  Database,
  ArrowRight,
  Search,
  CheckCircle2,
  Lock,
  Layers,
  Sparkles,
  KeyRound,
  Send,
  Download,
  Fingerprint,
  FileCheck,
  ScrollText,
  Cpu,
  ArrowUpRight,
  Info,
  Check,
  Package,
  Radio,
  FileSearch,
  Shield,
  Clock,
  ExternalLink,
} from 'lucide-react';
import {
  PageShell,
  PageHeader,
  Section,
  PrimaryButton,
  SecondaryButton,
  StatusBadge,
  VerificationBadge,
  KeyValueRow,
  TechnicalDetails,
} from './ui/designSystem';
import { ClassifiedDocument, Recipient, EncryptedPackage, DecryptionEvent } from '../types';
import { ActiveTab } from '../types/navigation';
import { airGappedLedger } from '../ledger/dlt';

interface OverviewViewProps {
  documents: ClassifiedDocument[];
  recipients: Recipient[];
  activePackage: EncryptedPackage | null;
  onNavigateTab: (tab: ActiveTab) => void;
  onRunWalkthroughDemo?: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  documents,
  recipients,
  activePackage,
  onNavigateTab,
}) => {
  const chain = airGappedLedger.getChain();
  const allEvents: DecryptionEvent[] = chain.flatMap((b) => b.transactions);

  return (
    <PageShell>
      {/* PAGE HEADER */}
      <PageHeader
        title="Workstation Overview"
        description="Air-gapped post-quantum document distribution, recipient-bound steganographic attribution, and immutable provenance ledger."
        badge={
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            Operational &bull; FIPS 203/204
          </span>
        }
        action={
          <div className="flex items-center gap-2">
            <SecondaryButton
              size="sm"
              icon={<Search className="w-3.5 h-3.5 text-slate-500" />}
              onClick={() => onNavigateTab('forensics')}
            >
              Forensic investigation
            </SecondaryButton>
            <PrimaryButton
              size="sm"
              icon={<FileText className="w-3.5 h-3.5" />}
              onClick={() => onNavigateTab('documents')}
            >
              Distribute document
            </PrimaryButton>
          </div>
        }
      />

      {/* 1. PINNED LIVE SYSTEM STATUS CARDS */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        {/* Environment */}
        <div className="p-4 bg-white rounded-xl border border-slate-200/90 shadow-2xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium text-slate-500">
              Isolation Boundary
            </span>
            <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
          </div>
          <div className="text-sm font-semibold text-slate-900 truncate">
            Air-Gapped Local
          </div>
          <span className="text-[11px] text-slate-500 block truncate">
            Zero telemetry &bull; Host memory isolated
          </span>
        </div>

        {/* Ledger Health */}
        <div className="p-4 bg-white rounded-xl border border-slate-200/90 shadow-2xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium text-slate-500">
              DLT Provenance Ledger
            </span>
            <VerificationBadge label="4/4 Quorum" />
          </div>
          <div className="text-sm font-semibold text-slate-900">
            {chain.length} {chain.length === 1 ? 'Block' : 'Blocks'} Composed
          </div>
          <span className="text-[11px] text-slate-500 block truncate">
            {allEvents.length} Decryption {allEvents.length === 1 ? 'event' : 'events'} recorded
          </span>
        </div>

        {/* Cryptographic Readiness */}
        <div className="p-4 bg-white rounded-xl border border-slate-200/90 shadow-2xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium text-slate-500">
              Post-Quantum Suite
            </span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-50 text-indigo-700 border border-indigo-200/80">
              NIST 2024
            </span>
          </div>
          <div className="text-sm font-semibold text-slate-900">
            ML-KEM &bull; ML-DSA
          </div>
          <span className="text-[11px] text-slate-500 block truncate">
            ML-KEM-768 &bull; ML-DSA-65 &bull; AES-256-GCM
          </span>
        </div>

        {/* Protected Assets */}
        <div className="p-4 bg-white rounded-xl border border-slate-200/90 shadow-2xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium text-slate-500">
              Registered Inventory
            </span>
            {activePackage ? (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-50 text-amber-700 border border-amber-200">
                Package Ready
              </span>
            ) : (
              <span className="text-[10px] text-slate-400">Idle</span>
            )}
          </div>
          <div className="text-sm font-semibold text-slate-900">
            {documents.length} Docs &bull; {recipients.length} Identities
          </div>
          <span className="text-[11px] text-slate-500 block truncate">
            {activePackage ? `Active: ${activePackage.documentTitle}` : 'Ready for distribution'}
          </span>
        </div>
      </div>

      {/* 2. INTRODUCTION — "START HERE" */}
      <div className="bg-gradient-to-br from-slate-900 to-slate-800 text-white rounded-xl p-5 sm:p-6 shadow-sm border border-slate-800">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                START HERE &bull; AEGIS-PQC
              </span>
              <span className="text-xs text-slate-400">
                SIH Problem Statement 26237
              </span>
            </div>
            <h2 className="text-lg sm:text-xl font-bold tracking-tight text-white">
              What AEGIS-PQC Does
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              AEGIS-PQC encrypts sensitive documents for authorized recipients and binds an invisible, recipient-unique forensic watermark to every authorized decryption. Each decryption event is signed with post-quantum cryptography and permanently sealed into an immutable air-gapped ledger. If a document is later leaked, investigators can extract the watermark to definitively identify who decrypted it and mathematically verify the provenance trail.
            </p>
          </div>

          <div className="shrink-0 flex flex-wrap sm:flex-col gap-2.5">
            <button
              onClick={() => onNavigateTab('documents')}
              className="inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-all shadow-xs cursor-pointer"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>1. Encrypt a Document</span>
            </button>
            <button
              onClick={() => onNavigateTab('decrypt')}
              className="inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all cursor-pointer"
            >
              <Lock className="w-3.5 h-3.5 text-indigo-400" />
              <span>2. Decrypt as Recipient</span>
            </button>
            <button
              onClick={() => onNavigateTab('forensics')}
              className="inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all cursor-pointer"
            >
              <Search className="w-3.5 h-3.5 text-amber-400" />
              <span>3. Investigate Leak</span>
            </button>
          </div>
        </div>

        {/* ACTIVE PACKAGE BANNER (IF IN PIPELINE) */}
        {activePackage && (
          <div className="mt-5 pt-4 border-t border-slate-700/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-800/60 -mx-5 -mb-5 sm:-mx-6 sm:-mb-6 p-4 rounded-b-xl">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-400/30 flex items-center justify-center shrink-0">
                <Package className="w-4 h-4 text-indigo-300" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-white truncate">
                    Active In-Flight Package: {activePackage.documentTitle}
                  </span>
                  <span className="font-mono text-[10px] text-slate-400 px-1.5 py-0.2 bg-slate-900 rounded">
                    {activePackage.packageId.slice(0, 10)}...
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 truncate">
                  Encrypted for {activePackage.envelopes.length} authorized {activePackage.envelopes.length === 1 ? 'recipient' : 'recipients'} &bull; Ready for recipient decryption or forensic testing.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={() => onNavigateTab('decrypt')}
                className="px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <span>Decrypt this package</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* 3. COMPLETE 8-STEP END-TO-END WORKFLOW GUIDE */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-200">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base sm:text-lg font-bold text-slate-900">
                End-to-End Operational Workflow
              </h2>
              <span className="text-xs font-medium text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
                8 Guided Steps
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Follow this sequence from sender key review to recipient decryption, forensic recovery, and ledger auditing.
            </p>
          </div>
          <span className="text-[11px] text-slate-400 shrink-0 font-medium">
            Click any step action to jump directly to that station
          </span>
        </div>

        {/* WORKFLOW CARDS CONTAINER */}
        <div className="space-y-3">
          {/* STEP 1: REVIEW IDENTITY */}
          <div className="bg-white rounded-xl border border-slate-200/90 shadow-2xs p-4 sm:p-5 hover:border-slate-300 transition-all">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200/80 flex items-center justify-center shrink-0 text-xs font-bold text-indigo-700">
                  01
                </div>
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-indigo-600">
                      Step 1 &bull; Identity & Setup
                    </span>
                    <span className="text-slate-300">&bull;</span>
                    <h3 className="text-sm font-semibold text-slate-900">
                      Review Workstation Identity & Cryptographic Keys
                    </h3>
                    <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                      Identity Station
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed max-w-3xl">
                    Review the active sender identity and cryptographic certificates. Confirm that your post-quantum keypairs (ML-KEM-768 for decapsulation and ML-DSA-65 for signing) are loaded, valid, and bound to your current session before encrypting or distributing materials.
                  </p>
                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px]">
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Destination:</span>
                      <code className="text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded">Identity</code>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Expected Output:</span>
                      <span>Verified active keypair status & fingerprint certificates.</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="shrink-0 flex items-center md:self-center">
                <SecondaryButton
                  size="sm"
                  icon={<KeyRound className="w-3.5 h-3.5 text-indigo-600" />}
                  onClick={() => onNavigateTab('identity')}
                >
                  Inspect Identity
                </SecondaryButton>
              </div>
            </div>
          </div>

          {/* STEP 2: REVIEW RECIPIENTS */}
          <div className="bg-white rounded-xl border border-slate-200/90 shadow-2xs p-4 sm:p-5 hover:border-slate-300 transition-all">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200/80 flex items-center justify-center shrink-0 text-xs font-bold text-indigo-700">
                  02
                </div>
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-indigo-600">
                      Step 2 &bull; Recipient Directory
                    </span>
                    <span className="text-slate-300">&bull;</span>
                    <h3 className="text-sm font-semibold text-slate-900">
                      Review Enrolled Recipients & Clearance Levels
                    </h3>
                    <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                      {recipients.length} Enrolled
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed max-w-3xl">
                    Verify the intended recipient identities and confirm their individual ML-KEM-768 public keys and clearance levels. Documents are encrypted once, but each recipient receives an independently encapsulated symmetric key capsule.
                  </p>
                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px]">
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Destination:</span>
                      <code className="text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded">Recipients</code>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Expected Output:</span>
                      <span>Enrolled directory with public key certificates ready for key encapsulation.</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="shrink-0 flex items-center md:self-center">
                <SecondaryButton
                  size="sm"
                  icon={<Users className="w-3.5 h-3.5 text-indigo-600" />}
                  onClick={() => onNavigateTab('recipients')}
                >
                  Review Recipients
                </SecondaryButton>
              </div>
            </div>
          </div>

          {/* STEP 3: ENCRYPT AND EXPORT A DOCUMENT */}
          <div className="bg-white rounded-xl border border-slate-200/90 shadow-2xs p-4 sm:p-5 hover:border-slate-300 transition-all">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200/80 flex items-center justify-center shrink-0 text-xs font-bold text-indigo-700">
                  03
                </div>
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-indigo-600">
                      Step 3 &bull; Document Encryption
                    </span>
                    <span className="text-slate-300">&bull;</span>
                    <h3 className="text-sm font-semibold text-slate-900">
                      Encrypt Document & Export Encrypted Package (.sihpkg)
                    </h3>
                    <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                      AES-256-GCM + ML-KEM-768
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed max-w-3xl">
                    Select a classified document or upload a new PDF. Choose authorized recipients from the directory and run encryption. The engine encrypts the payload with AES-256-GCM, encapsulates individual keys with ML-KEM-768, and compiles the signed <span className="font-mono text-slate-800 font-medium">.sihpkg</span> distribution package.
                  </p>
                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px]">
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Destination:</span>
                      <code className="text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded">Documents</code>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Expected Output:</span>
                      <span className="font-medium text-slate-700">
                        Exportable <code className="text-slate-800 bg-slate-100 px-1 py-0.2 rounded">.sihpkg</code> package ready for recipient distribution.
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="shrink-0 flex items-center md:self-center">
                <PrimaryButton
                  size="sm"
                  icon={<FileText className="w-3.5 h-3.5" />}
                  onClick={() => onNavigateTab('documents')}
                >
                  Encrypt & Export
                </PrimaryButton>
              </div>
            </div>
          </div>

          {/* STEP 4: TRANSFER THE PACKAGE */}
          <div className="bg-white rounded-xl border border-slate-200/90 shadow-2xs p-4 sm:p-5 hover:border-slate-300 transition-all">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-300 flex items-center justify-center shrink-0 text-xs font-bold text-slate-700">
                  04
                </div>
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-600">
                      Step 4 &bull; Package Distribution
                    </span>
                    <span className="text-slate-300">&bull;</span>
                    <h3 className="text-sm font-semibold text-slate-900">
                      Transfer Package to the Recipient Workstation
                    </h3>
                    <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                      In-Memory Pipeline or File Export
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed max-w-3xl">
                    Transfer the exported <span className="font-mono text-slate-800 font-medium">.sihpkg</span> package to the recipient. AEGIS-PQC supports direct export as a file for air-gapped USB/optical transfer, peer synchronization, or seamless in-memory transfer to the Recipient Portal on this workstation.
                  </p>
                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px]">
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Supported Methods:</span>
                      <span>Download file from Documents or open directly in the Decrypt portal.</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Expected Output:</span>
                      <span>Encrypted envelope loaded in the Recipient Decryption environment.</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="shrink-0 flex items-center gap-2 md:self-center">
                <SecondaryButton
                  size="sm"
                  icon={<Download className="w-3.5 h-3.5 text-slate-500" />}
                  onClick={() => onNavigateTab('documents')}
                >
                  View Package (Documents)
                </SecondaryButton>
                <SecondaryButton
                  size="sm"
                  icon={<ArrowRight className="w-3.5 h-3.5 text-slate-500" />}
                  onClick={() => onNavigateTab('decrypt')}
                >
                  Open in Decrypt
                </SecondaryButton>
              </div>
            </div>
          </div>

          {/* STEP 5: DECRYPT AS THE INTENDED RECIPIENT */}
          <div className="bg-white rounded-xl border border-slate-200/90 shadow-2xs p-4 sm:p-5 hover:border-slate-300 transition-all">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200/80 flex items-center justify-center shrink-0 text-xs font-bold text-indigo-700">
                  05
                </div>
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-indigo-600">
                      Step 5 &bull; Authorized Decryption
                    </span>
                    <span className="text-slate-300">&bull;</span>
                    <h3 className="text-sm font-semibold text-slate-900">
                      Decrypt Package as Authorized Recipient (Forensic Binding)
                    </h3>
                    <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                      Invisible Steganography Bound
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed max-w-3xl">
                    Import the package into the Decrypt portal, select your recipient identity, provide authentication, and perform ML-KEM-768 decapsulation. Before releasing the plaintext, the engine embeds an invisible recipient-unique watermark and logs a signed decryption event to the ledger.
                  </p>
                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px]">
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Destination:</span>
                      <code className="text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded">Decrypt</code>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Expected Output:</span>
                      <span className="font-medium text-slate-700">
                        Decrypted document with embedded recipient watermark + signed ledger block transaction.
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="shrink-0 flex items-center md:self-center">
                <PrimaryButton
                  size="sm"
                  icon={<Lock className="w-3.5 h-3.5" />}
                  onClick={() => onNavigateTab('decrypt')}
                >
                  Decrypt Document
                </PrimaryButton>
              </div>
            </div>
          </div>

          {/* STEP 6: INVESTIGATE FORENSIC EVIDENCE */}
          <div className="bg-white rounded-xl border border-slate-200/90 shadow-2xs p-4 sm:p-5 hover:border-slate-300 transition-all">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200/80 flex items-center justify-center shrink-0 text-xs font-bold text-indigo-700">
                  06
                </div>
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-indigo-600">
                      Step 6 &bull; Forensic Extraction
                    </span>
                    <span className="text-slate-300">&bull;</span>
                    <h3 className="text-sm font-semibold text-slate-900">
                      Investigate Leaked Material & Recover Attribution
                    </h3>
                    <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200">
                      Zero-Width Steganography Analysis
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed max-w-3xl">
                    Upload suspected leaked text or PDF files. The forensic engine inspects binary zero-width character sequences, validates CRC-16 checksums, and attributes the exact recipient who decrypted the file. Successful attribution requires genuine cryptographic verification against the ledger records.
                  </p>
                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px]">
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Destination:</span>
                      <code className="text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded">Forensics</code>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Expected Output:</span>
                      <span className="font-medium text-slate-700">
                        Extracted Watermark ID, Attributed Recipient identity, and provenance confirmation.
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="shrink-0 flex items-center md:self-center">
                <SecondaryButton
                  size="sm"
                  icon={<Search className="w-3.5 h-3.5 text-amber-600" />}
                  onClick={() => onNavigateTab('forensics')}
                >
                  Analyze Leak
                </SecondaryButton>
              </div>
            </div>
          </div>

          {/* STEP 7: VERIFY SUPPORTING EVIDENCE */}
          <div className="bg-white rounded-xl border border-slate-200/90 shadow-2xs p-4 sm:p-5 hover:border-slate-300 transition-all">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200/80 flex items-center justify-center shrink-0 text-xs font-bold text-indigo-700">
                  07
                </div>
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-indigo-600">
                      Step 7 &bull; Cryptographic Audit
                    </span>
                    <span className="text-slate-300">&bull;</span>
                    <h3 className="text-sm font-semibold text-slate-900">
                      Verify Signatures, Merkle Proofs & Integrity Checks
                    </h3>
                    <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                      FIPS 204 Lattice Signature Verification
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed max-w-3xl">
                    Run mathematical checks across all artifacts. Confirm that the ML-DSA-65 signature on the decryption transaction is cryptographically genuine, verify the Merkle inclusion proof against the ledger block root, and inspect hash chain continuity.
                  </p>
                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px]">
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Destination:</span>
                      <code className="text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded">Verification</code>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Expected Output:</span>
                      <span>Independent pass/fail verdict on digital signatures and Merkle tree roots.</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="shrink-0 flex items-center md:self-center">
                <SecondaryButton
                  size="sm"
                  icon={<FileCheck className="w-3.5 h-3.5 text-emerald-600" />}
                  onClick={() => onNavigateTab('verification')}
                >
                  Verify Evidence
                </SecondaryButton>
              </div>
            </div>
          </div>

          {/* STEP 8: INSPECT PROVENANCE AND AUDIT RECORDS */}
          <div className="bg-white rounded-xl border border-slate-200/90 shadow-2xs p-4 sm:p-5 hover:border-slate-300 transition-all">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200/80 flex items-center justify-center shrink-0 text-xs font-bold text-indigo-700">
                  08
                </div>
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-indigo-600">
                      Step 8 &bull; Ledger & Governance
                    </span>
                    <span className="text-slate-300">&bull;</span>
                    <h3 className="text-sm font-semibold text-slate-900">
                      Inspect Immutable Ledger Blocks & System Audit Logs
                    </h3>
                    <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                      Immutable Chain of Custody
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed max-w-3xl">
                    Inspect the decentralized immutable ledger. Examine block headers, state hashes, validator consensus seals, and chronological audit trail logs to ensure zero-trust compliance, non-repudiation, and defense-grade evidentiary certainty.
                  </p>
                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px]">
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Destinations:</span>
                      <code className="text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded">Ledger</code>
                      <span className="text-slate-400">and</span>
                      <code className="text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded">Audit</code>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <span className="font-semibold text-slate-700">Expected Output:</span>
                      <span>Cryptographically sealed blocks with validator signatures and immutable timestamps.</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="shrink-0 flex items-center gap-2 md:self-center">
                <SecondaryButton
                  size="sm"
                  icon={<Database className="w-3.5 h-3.5 text-indigo-600" />}
                  onClick={() => onNavigateTab('ledger')}
                >
                  Explore Ledger
                </SecondaryButton>
                <SecondaryButton
                  size="sm"
                  icon={<ScrollText className="w-3.5 h-3.5 text-slate-600" />}
                  onClick={() => onNavigateTab('audit')}
                >
                  Audit Center
                </SecondaryButton>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 4. RECENT PROVENANCE ACTIVITY SECTION */}
      <Section
        title="Recent Provenance Activity"
        description="Chronological decryption events attested and signed into the air-gapped ledger by validator quorum."
        action={
          <button
            onClick={() => onNavigateTab('ledger')}
            className="text-xs font-semibold text-indigo-600 hover:text-indigo-700 flex items-center gap-1 cursor-pointer transition-colors"
          >
            <span>View all in Ledger Explorer</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        }
      >
        {allEvents.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-400 space-y-2">
            <p>No decryption events recorded yet.</p>
            <p className="text-slate-500">
              Complete an authorized decryption in <button onClick={() => onNavigateTab('decrypt')} className="text-indigo-600 hover:underline font-medium">Decrypt</button> to record your first immutable provenance block.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-100 -mx-4 -mb-4 sm:-mx-6 sm:-mb-6 overflow-x-auto">
            {allEvents.slice(-5).reverse().map((ev) => (
              <div
                key={ev.eventId}
                className="px-4 sm:px-6 py-3.5 flex items-center justify-between gap-4 hover:bg-slate-50/70 transition-colors text-xs"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-900 truncate">
                      {ev.recipientName}
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono bg-slate-100 px-1.5 py-0.2 rounded">
                      {ev.eventId}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 truncate flex items-center gap-2">
                    <span>{ev.documentTitle}</span>
                    <span className="text-slate-300">&bull;</span>
                    <span>Watermark: <span className="font-mono text-slate-700 font-medium">{ev.watermarkId}</span></span>
                  </div>
                </div>

                <div className="shrink-0 flex items-center gap-3">
                  <div className="text-right">
                    <span className="text-[11px] text-slate-500 block">
                      {new Date(ev.timestampEpochMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                    <span className="text-[10px] text-slate-400 block font-mono">
                      {new Date(ev.timestampEpochMs).toLocaleDateString()}
                    </span>
                  </div>
                  <VerificationBadge label="Signature valid" />
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* 5. COLLAPSIBLE TECHNICAL DETAILS ACCORDION */}
      <TechnicalDetails
        title="Technical Specifications & Cryptographic Parameter Sets"
        defaultOpen={false}
      >
        <KeyValueRow
          label="Key Encapsulation Mechanism (KEM)"
          value="NIST FIPS 203 (ML-KEM-768) Module-Lattice Key Encapsulation (Post-Quantum Security Level 3)"
          mono={false}
        />
        <KeyValueRow
          label="Digital Signature Algorithm (DSA)"
          value="NIST FIPS 204 (ML-DSA-65) Module-Lattice Digital Signature (Post-Quantum Non-Repudiation)"
          mono={false}
        />
        <KeyValueRow
          label="Symmetric Bulk Cipher"
          value="AES-256-GCM (NIST SP 800-38D) with 96-bit unique IV and 128-bit authentication tag"
          mono={false}
        />
        <KeyValueRow
          label="Key Derivation Function"
          value="HKDF-SHA256 (RFC 5869) with domain-separated salt and recipient identity binding"
          mono={false}
        />
        <KeyValueRow
          label="Steganographic Capacity & Encoding"
          value="Zero-width whitespace encoding (\u200B, \u200C, \u200D) with 16-bit sync marker (0xA55A) and CRC-16 integrity checksum"
          mono={false}
        />
        <KeyValueRow
          label="Distributed Ledger Consensus"
          value="4-Node Air-Gapped Byzantine/Quorum Consensus with Merkle tree transaction roots and SHA-256 block chaining"
          mono={false}
        />
        <KeyValueRow
          label="Document Container Format"
          value=".sihpkg sealed envelope with JSON envelope header, recipient encapsulation table, and AES ciphertext payload"
          mono={false}
        />
      </TechnicalDetails>
    </PageShell>
  );
};
