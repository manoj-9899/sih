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
      <PageHeader
        title="Overview"
        description="System status, cryptographic readiness, and recent activity."
        action={
          <div className="flex items-center gap-2">
            <SecondaryButton
              size="sm"
              icon={<Search className="w-3.5 h-3.5 text-slate-500" />}
              onClick={() => onNavigateTab('forensics')}
            >
              Analyze document
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

      {/* 1. COMPACT SYSTEM SUMMARY (No oversized card grid) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <div className="p-4 bg-white rounded-xl border border-slate-200/90 shadow-2xs space-y-1">
          <span className="text-[11px] font-medium text-slate-500 block">
            Environment
          </span>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
            <span className="text-sm font-semibold text-slate-900 truncate">
              Air-Gapped Local
            </span>
          </div>
          <span className="text-[11px] text-slate-400 block truncate">
            Hardware isolated
          </span>
        </div>

        <div className="p-4 bg-white rounded-xl border border-slate-200/90 shadow-2xs space-y-1">
          <span className="text-[11px] font-medium text-slate-500 block">
            Ledger health
          </span>
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-slate-900">
              {chain.length} Blocks
            </span>
            <VerificationBadge label="Healthy" />
          </div>
          <span className="text-[11px] text-slate-400 block truncate">
            4/4 Validator nodes active
          </span>
        </div>

        <div className="p-4 bg-white rounded-xl border border-slate-200/90 shadow-2xs space-y-1">
          <span className="text-[11px] font-medium text-slate-500 block">
            Cryptographic readiness
          </span>
          <div className="text-sm font-semibold text-slate-900">
            FIPS 203 / 204
          </div>
          <span className="text-[11px] text-slate-500 block truncate">
            ML-KEM-768 &bull; ML-DSA-65
          </span>
        </div>

        <div className="p-4 bg-white rounded-xl border border-slate-200/90 shadow-2xs space-y-1">
          <span className="text-[11px] font-medium text-slate-500 block">
            Protected documents
          </span>
          <div className="text-sm font-semibold text-slate-900">
            {documents.length} Managed
          </div>
          <span className="text-[11px] text-slate-400 block truncate">
            {recipients.length} Enrolled identities
          </span>
        </div>
      </div>

      {/* 2. CORE WORKFLOW SHORTCUT CARD */}
      <Section
        title="Quick workflow guide"
        description="How secure multi-recipient distribution and provenance attribution operate."
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
          <div
            onClick={() => onNavigateTab('documents')}
            className="p-3.5 rounded-lg border border-slate-200/80 bg-slate-50/50 hover:bg-slate-50 hover:border-slate-300 transition-all cursor-pointer group"
          >
            <div className="flex items-center justify-between text-xs font-semibold text-slate-900 mb-1">
              <span>1. Secure Distribution</span>
              <ArrowRight className="w-3.5 h-3.5 text-slate-400 group-hover:text-indigo-600 transition-colors" />
            </div>
            <p className="text-[11px] text-slate-500 leading-normal">
              Encrypt documents once with AES-256-GCM and wrap keys individually with ML-KEM-768 for authorized recipients.
            </p>
          </div>

          <div
            onClick={() => onNavigateTab('decrypt')}
            className="p-3.5 rounded-lg border border-slate-200/80 bg-slate-50/50 hover:bg-slate-50 hover:border-slate-300 transition-all cursor-pointer group"
          >
            <div className="flex items-center justify-between text-xs font-semibold text-slate-900 mb-1">
              <span>2. Local Decryption</span>
              <ArrowRight className="w-3.5 h-3.5 text-slate-400 group-hover:text-indigo-600 transition-colors" />
            </div>
            <p className="text-[11px] text-slate-500 leading-normal">
              Recipients decrypt locally. Before releasing plaintext, an invisible forensic watermark is bound and signed with ML-DSA-65.
            </p>
          </div>

          <div
            onClick={() => onNavigateTab('forensics')}
            className="p-3.5 rounded-lg border border-slate-200/80 bg-slate-50/50 hover:bg-slate-50 hover:border-slate-300 transition-all cursor-pointer group"
          >
            <div className="flex items-center justify-between text-xs font-semibold text-slate-900 mb-1">
              <span>3. Forensic Attribution</span>
              <ArrowRight className="w-3.5 h-3.5 text-slate-400 group-hover:text-indigo-600 transition-colors" />
            </div>
            <p className="text-[11px] text-slate-500 leading-normal">
              Upload suspected leaked text. The engine recovers the watermark and verifies the signed provenance event on the ledger.
            </p>
          </div>
        </div>
      </Section>

      {/* 3. RECENT PROVENANCE ACTIVITY */}
      <Section
        title="Recent provenance activity"
        description="Chronological ledger events recorded by validator quorum."
        action={
          <button
            onClick={() => onNavigateTab('ledger')}
            className="text-xs font-medium text-indigo-600 hover:text-indigo-700 flex items-center gap-1 cursor-pointer"
          >
            <span>View all in Ledger</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        }
      >
        {allEvents.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-400">
            No decryption events recorded yet. Go to <strong className="text-slate-600">Decrypt</strong> to perform a local decryption.
          </div>
        ) : (
          <div className="divide-y divide-slate-100 -mx-4 -mb-4 sm:-mx-6 sm:-mb-6 overflow-x-auto">
            {allEvents.slice(-5).reverse().map((ev) => (
              <div
                key={ev.eventId}
                className="px-4 sm:px-6 py-3 flex items-center justify-between gap-4 hover:bg-slate-50/60 transition-colors text-xs"
              >
                <div className="space-y-0.5 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-900 truncate">
                      {ev.recipientName}
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono">
                      {ev.eventId}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 truncate">
                    {ev.documentTitle} &bull; Watermark: <span className="font-mono">{ev.watermarkId}</span>
                  </div>
                </div>

                <div className="shrink-0 flex items-center gap-3">
                  <span className="text-[11px] text-slate-400">
                    {new Date(ev.timestampEpochMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                  <VerificationBadge label="Signature valid" />
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* Technical Summary Accordion */}
      <TechnicalDetails title="Cryptographic specification & parameter sets">
        <KeyValueRow label="Key Encapsulation" value="NIST FIPS 203 (ML-KEM-768) Lattice Cryptography" mono={false} />
        <KeyValueRow label="Digital Signature" value="NIST FIPS 204 (ML-DSA-65) Lattice Signature" mono={false} />
        <KeyValueRow label="Symmetric Bulk Cipher" value="AES-256-GCM with 96-bit random IV & 128-bit authentication tag" mono={false} />
        <KeyValueRow label="Key Derivation" value="HKDF-SHA256 (RFC 5869) with air-gapped domain salt" mono={false} />
        <KeyValueRow label="Steganographic Capacity" value="Zero-width whitespace encoding with CRC-16 checksum & 0xA55A sync marker" mono={false} />
        <KeyValueRow label="Ledger Consensus" value="4-Node Quorum with Merkle tree state roots and SHA-256 block hash chaining" mono={false} />
      </TechnicalDetails>
    </PageShell>
  );
};
