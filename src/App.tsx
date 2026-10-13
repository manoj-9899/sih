/**
 * Main Application Component:
 * Cryptographic Attribution and Immutable Decryption Provenance System.
 * Production-grade minimalist security & digital forensics UI architecture.
 */

import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { ActiveTab } from './types/navigation';
import { OverviewView } from './components/OverviewView';
import { DocumentsView } from './components/DocumentsView';
import { RecipientsView } from './components/RecipientsView';
import { DecryptView } from './components/DecryptView';
import { ForensicsView } from './components/ForensicsView';
import { LedgerView } from './components/LedgerView';
import { IdentityView } from './components/IdentityView';
import { VerificationView } from './components/VerificationView';
import { AuditCenterView } from './components/AuditCenterView';
import { SettingsView } from './components/SettingsView';
import { GuidedTourIntroModal } from './components/guided/GuidedTourIntroModal';
import { FloatingMissionGuide } from './components/guided/FloatingMissionGuide';
import { TOUR_STEPS } from './types/tour';
import {
  SAMPLE_DOCUMENTS,
  initializeRecipientsAndLedger,
} from './data/sampleData';
import { Recipient, EncryptedPackage, ClassifiedDocument } from './types';
import { airGappedLedger } from './ledger/dlt';
import { DistributionService } from './services/distributionService';
import { sessionManager } from './crypto/sessionManager';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [mobileNavOpen, setMobileNavOpen] = useState<boolean>(false);
  const [recipients, setRecipients] = useState<Recipient[]>([]);
  const [documents, setDocuments] = useState<ClassifiedDocument[]>(SAMPLE_DOCUMENTS);
  const [activePackage, setActivePackage] = useState<EncryptedPackage | null>(null);
  const [leakedText, setLeakedText] = useState<string>('');
  const [leakedPdfBytes, setLeakedPdfBytes] = useState<Uint8Array | null>(null);
  const [leakedFileName, setLeakedFileName] = useState<string>('');
  const [leakedMeta, setLeakedMeta] = useState<{ title: string; recipientName: string } | null>(null);
  const [blocksCount, setBlocksCount] = useState<number>(1);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Guided Detective Tour State
  const [showIntroModal, setShowIntroModal] = useState<boolean>(() => {
    const hasSeen = localStorage.getItem('sih26237_has_seen_tour_intro');
    return !hasSeen;
  });
  const [tourStepId, setTourStepId] = useState<number>(1);
  const [tourActive, setTourActive] = useState<boolean>(false);

  const handleAddDocument = (newDoc: ClassifiedDocument) => {
    setDocuments((prev) => [newDoc, ...prev]);
  };

  const handleRecipientAdded = (newRecip: Recipient) => {
    setRecipients((prev) => [...prev, newRecip]);
  };

  const handleResetSession = () => {
    setActivePackage(null);
    setLeakedText('');
    setLeakedPdfBytes(null);
    setLeakedFileName('');
    setLeakedMeta(null);
  };

  // Initialize PQC keys and Genesis block
  useEffect(() => {
    const init = async () => {
      try {
        const recips = await initializeRecipientsAndLedger();
        setRecipients(recips);
        setBlocksCount(airGappedLedger.getChain().length);
      } catch (err) {
        console.error('Initialization error:', err);
      } finally {
        setIsLoading(false);
      }
    };
    init();
  }, []);

  // Visual Spotlight Manager based on active tour step
  useEffect(() => {
    if (!tourActive) {
      document.querySelectorAll('.tour-spotlight-active').forEach((el) => {
        el.classList.remove('tour-spotlight-active');
      });
      return;
    }

    const currentStep = TOUR_STEPS.find((s) => s.id === tourStepId);
    if (!currentStep || !currentStep.highlightSelector) return;

    const timeout = setTimeout(() => {
      document.querySelectorAll('.tour-spotlight-active').forEach((el) => {
        el.classList.remove('tour-spotlight-active');
      });

      const targetEl = document.querySelector(currentStep.highlightSelector!);
      if (targetEl) {
        targetEl.classList.add('tour-spotlight-active');
      }
    }, 150);

    return () => clearTimeout(timeout);
  }, [tourActive, tourStepId, activeTab]);

  const refreshBlocksCount = () => {
    setBlocksCount(airGappedLedger.getChain().length);
  };

  const handleSimulateLeak = (
    text: string,
    metadata: { title: string; recipientName: string },
    pdfBytes?: Uint8Array,
    fileName?: string
  ) => {
    setLeakedText(text);
    setLeakedMeta(metadata);
    if (pdfBytes) {
      setLeakedPdfBytes(pdfBytes);
      setLeakedFileName(fileName || 'Leaked_Document.pdf');
    }
  };

  const handleStartTourFromIntro = () => {
    setShowIntroModal(false);
    localStorage.setItem('sih26237_has_seen_tour_intro', 'true');
    setTourActive(true);
    setTourStepId(1);
    setActiveTab('documents');
  };

  const handleDismissIntroModal = () => {
    setShowIntroModal(false);
    localStorage.setItem('sih26237_has_seen_tour_intro', 'true');
  };

  // 1-Click Failsafe Auto-Execution for whichever step the beginner is on
  const handleAutoExecuteCurrentStep = async () => {
    const alice = recipients.find((r) => r.id === 'USR-ALICE-VANCE-01') || recipients[0];
    const bob = recipients.find((r) => r.id === 'USR-BOB-MARTINEZ-02') || recipients[1];
    const doc = documents[0];

    try {
      if (tourStepId === 1) {
        // Step 1: Create package with Alice & Bob
        const pkg = await DistributionService.createEncryptedPackage(doc, [alice, bob]);
        setActivePackage(pkg);
        setTourStepId(2);
        setActiveTab('decrypt');
      } else if (tourStepId === 2) {
        // Step 2: Ensure package exists and decrypt for Alice
        let pkg = activePackage;
        if (!pkg) {
          pkg = await DistributionService.createEncryptedPackage(doc, [alice, bob]);
          setActivePackage(pkg);
        }
        // Create authenticated session for Alice
        const aliceSession = await sessionManager.createSession(alice, 'AliceVance2026!');
        await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
        refreshBlocksCount();
        setTourStepId(3);
        setActiveTab('decrypt');
      } else if (tourStepId === 3) {
        // Step 3: Decrypt for Bob and leak
        let pkg = activePackage;
        if (!pkg) {
          pkg = await DistributionService.createEncryptedPackage(doc, [alice, bob]);
          setActivePackage(pkg);
        }
        // Create authenticated session for Bob
        const bobSession = await sessionManager.createSession(bob, 'BobMartinez2026!');
        const bRes = await DistributionService.executeRecipientDecryption(pkg, bob, bobSession);
        refreshBlocksCount();
        handleSimulateLeak(
          bRes.watermarkedText,
          {
            title: pkg.documentTitle,
            recipientName: bob.name,
          },
          bRes.decryptedBytes,
          `${pkg.documentTitle.replace(/\s+/g, '_')}_Leaked_BM.pdf`
        );
        setTourStepId(4);
        setActiveTab('forensics');
      } else if (tourStepId === 4) {
        // Step 4: Run forensics
        setTourStepId(5);
        setActiveTab('ledger');
      } else if (tourStepId === 5) {
        // Step 5: Finished
        setActiveTab('overview');
        setTourActive(false);
      }
    } catch (e) {
      console.error('Auto-execute error:', e);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-50 flex flex-col items-center justify-center text-slate-800 space-y-3 font-sans">
        <div className="w-6 h-6 border-2 border-slate-300 border-t-indigo-600 rounded-full animate-spin" />
        <div className="text-xs font-semibold text-slate-700">
          Loading cryptographic keys and ledger state...
        </div>
        <p className="text-[11px] text-slate-400">
          NIST FIPS 203 (ML-KEM-768) &bull; FIPS 204 (ML-DSA-65)
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex font-sans antialiased">
      {/* Intro Modal on First Visit */}
      <GuidedTourIntroModal
        isOpen={showIntroModal}
        onStartTour={handleStartTourFromIntro}
        onDismiss={handleDismissIntroModal}
      />

      {/* Fixed Desktop Sidebar & Mobile Drawer */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        blocksCount={blocksCount}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        mobileOpen={mobileNavOpen}
        onCloseMobile={() => setMobileNavOpen(false)}
      />

      {/* Main Content Area (Scrolls Independently; offset for fixed desktop sidebar) */}
      <div
        className={`flex-1 flex flex-col min-w-0 transition-all duration-200 ${
          sidebarCollapsed ? 'lg:ml-16' : 'lg:ml-64'
        }`}
      >
        <TopBar
          activeTab={activeTab}
          activePackage={activePackage}
          blocksCount={blocksCount}
          onResetSession={handleResetSession}
          onOpenMobileNav={() => setMobileNavOpen(true)}
        />

        {/* Viewport Content */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8">
          {activeTab === 'overview' && (
            <OverviewView
              documents={documents}
              recipients={recipients}
              activePackage={activePackage}
              onNavigateTab={(tab) => setActiveTab(tab)}
            />
          )}

          {activeTab === 'documents' && (
            <DocumentsView
              documents={documents}
              recipients={recipients}
              activePackage={activePackage}
              onPackageCreated={(pkg) => {
                setActivePackage(pkg);
                if (tourActive) setTourStepId(2);
              }}
              onNavigateToDecrypt={() => {
                setActiveTab('decrypt');
                if (tourActive) setTourStepId(2);
              }}
              onAddDocument={handleAddDocument}
            />
          )}

          {activeTab === 'recipients' && (
            <RecipientsView
              recipients={recipients}
              onRecipientAdded={handleRecipientAdded}
            />
          )}

          {activeTab === 'decrypt' && (
            <DecryptView
              recipients={recipients}
              activePackage={activePackage}
              onPackageImported={(pkg) => setActivePackage(pkg)}
              onDecryptionSuccess={() => {
                refreshBlocksCount();
              }}
              onSimulateLeak={(txt, meta, pdfBytes, fileName) => {
                handleSimulateLeak(txt, meta, pdfBytes, fileName);
                if (tourActive) setTourStepId(4);
              }}
              onNavigateToForensics={() => {
                setActiveTab('forensics');
                if (tourActive) setTourStepId(4);
              }}
              onNavigateToLedger={() => {
                setActiveTab('ledger');
                if (tourActive) setTourStepId(5);
              }}
            />
          )}

          {activeTab === 'forensics' && (
            <ForensicsView
              initialLeakedText={leakedText}
              initialLeakedPdfBytes={leakedPdfBytes}
              initialLeakedFileName={leakedFileName}
              leakedMetadata={leakedMeta}
              documents={documents}
              onNavigateToLedger={() => {
                setActiveTab('ledger');
                if (tourActive) setTourStepId(5);
              }}
            />
          )}

          {activeTab === 'ledger' && (
            <LedgerView onRefreshNeeded={refreshBlocksCount} />
          )}

          {activeTab === 'identity' && (
            <IdentityView recipients={recipients} />
          )}

          {activeTab === 'verification' && (
            <VerificationView recipients={recipients} />
          )}

          {activeTab === 'audit' && (
            <AuditCenterView
              documents={documents}
              recipients={recipients}
              onNavigateToLedger={() => setActiveTab('ledger')}
              onNavigateToForensics={() => setActiveTab('forensics')}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView
              onResetSession={handleResetSession}
              onNavigateTab={(tab) => setActiveTab(tab)}
              onRefreshNeeded={refreshBlocksCount}
            />
          )}
        </main>

        {/* Floating Detective Guide Companion (Available if tour is started) */}
        {tourActive && (
          <FloatingMissionGuide
            currentStepId={tourStepId}
            onSelectStep={(sId) => setTourStepId(sId)}
            onNavigateTab={(tab) => setActiveTab(tab)}
            onCloseTour={() => setTourActive(false)}
            onAutoExecuteCurrentStep={handleAutoExecuteCurrentStep}
            activePackageAvailable={activePackage !== null}
            leakedTextAvailable={leakedText.length > 0}
          />
        )}

        {/* Clean Laboratory Workstation Footer */}
        <footer className="border-t border-slate-200/90 bg-white py-3 px-6 text-xs text-slate-500">
          <div className="max-w-6xl mx-auto flex flex-col sm:flex-row justify-between items-center gap-2">
            <span className="text-slate-600 font-medium">
              AEGIS-PQC &bull; Cryptographic Attribution and Immutable Decryption Provenance
            </span>
            <span className="text-slate-400 font-mono text-[11px]">
              NIST FIPS 203 (ML-KEM-768) &bull; NIST FIPS 204 (ML-DSA-65) &bull; 4-Node Consensus
            </span>
          </div>
        </footer>
      </div>
    </div>
  );
}
