import React, { useState, useEffect } from 'react';
import { Menu, Shield, RefreshCw, Radio, Lock } from 'lucide-react';
import { ActiveTab } from '../types/navigation';
import { EncryptedPackage } from '../types';
import { sessionManager, AuthenticatedSession } from '../crypto/sessionManager';

interface TopBarProps {
  activeTab: ActiveTab;
  activePackage: EncryptedPackage | null;
  blocksCount: number;
  onResetSession: () => void;
  onOpenMobileNav: () => void;
}

const TAB_TITLES: Record<ActiveTab, { title: string; subtitle: string }> = {
  overview: {
    title: 'Overview',
    subtitle: 'System status, cryptographic readiness, and recent activity.',
  },
  documents: {
    title: 'Documents',
    subtitle: 'Manage protected documents and prepare secure distribution.',
  },
  recipients: {
    title: 'Recipients',
    subtitle: 'Manage authorized recipients and local cryptographic identities.',
  },
  decrypt: {
    title: 'Decrypt document',
    subtitle: 'Decrypt locally and create a signed provenance record.',
  },
  forensics: {
    title: 'Forensic verification',
    subtitle: 'Upload a leaked document to identify its originating decryption event.',
  },
  ledger: {
    title: 'Ledger',
    subtitle: 'Tamper-evident provenance for verified decryption events.',
  },
  identity: {
    title: 'Cryptographic identities',
    subtitle: 'Manage post-quantum identities used to protect access and verify decryption events.',
  },
  verification: {
    title: 'Security verification',
    subtitle: 'Test the platform against defined attack scenarios.',
  },
  audit: {
    title: 'Security Operations & Audit Center',
    subtitle: 'Cryptographic hash-chained audit log, threat detection, and end-to-end evidence visibility.',
  },
  settings: {
    title: 'Settings',
    subtitle: 'System configuration, air-gap boundary, and consensus parameters.',
  },
};

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  activePackage,
  blocksCount,
  onResetSession,
  onOpenMobileNav,
}) => {
  const [activeSession, setActiveSession] = useState<AuthenticatedSession | null>(() =>
    sessionManager.getActiveSession()
  );

  useEffect(() => {
    const unsub = sessionManager.subscribe((s) => setActiveSession(s));
    return unsub;
  }, []);

  const current = TAB_TITLES[activeTab] || {
    title: 'Overview',
    subtitle: 'Security & Forensics Platform',
  };

  return (
    <header className="h-14 bg-white/90 backdrop-blur-xs border-b border-slate-200/80 px-4 sm:px-6 flex items-center justify-between sticky top-0 z-20">
      {/* Left: Mobile hamburger & Context title */}
      <div className="flex items-center gap-3 min-w-0">
        <button
          onClick={onOpenMobileNav}
          className="lg:hidden p-1.5 text-slate-500 hover:text-slate-900 rounded-md hover:bg-slate-100 transition-colors cursor-pointer"
          aria-label="Open navigation menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2 min-w-0">
          <span className="text-sm font-semibold text-slate-900 truncate">
            {current.title}
          </span>
          <span className="text-slate-300 hidden md:inline">/</span>
          <span className="text-xs text-slate-500 font-normal truncate hidden md:inline">
            {current.subtitle}
          </span>
        </div>
      </div>

      {/* Right: Active Session Status & minimal controls */}
      <div className="flex items-center gap-3 shrink-0">
        {activeSession ? (
          <div className="flex items-center gap-2">
            <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-50 border border-emerald-200/80 text-[11px] text-emerald-800">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="font-semibold">{activeSession.userName}</span>
              <span className="text-[10px] text-emerald-600">({activeSession.userClearance})</span>
            </div>
            <button
              onClick={() => sessionManager.lockSession()}
              className="text-xs text-slate-500 hover:text-slate-800 flex items-center gap-1 px-2 py-1 rounded-md border border-slate-200 hover:bg-slate-50 transition-colors cursor-pointer"
              title="Lock active session"
            >
              <Lock className="w-3 h-3 text-slate-400" />
              <span className="hidden sm:inline">Lock</span>
            </button>
          </div>
        ) : (
          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-100 border border-slate-200 text-[11px] text-slate-600">
            <Lock className="w-3 h-3 text-slate-400" />
            <span>Session locked</span>
          </div>
        )}

        <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-100 border border-slate-200/80 text-[11px] text-slate-600 font-sans">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          <span>Local Enclave</span>
        </div>

        <button
          onClick={onResetSession}
          className="text-xs text-slate-500 hover:text-slate-800 flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-slate-200 hover:bg-slate-50 transition-colors cursor-pointer"
          title="Reset active package and demonstration state"
        >
          <RefreshCw className="w-3 h-3 text-slate-400" />
          <span className="hidden sm:inline">Reset demo</span>
        </button>
      </div>
    </header>
  );
};
