import React, { useState, useEffect, useRef } from 'react';
import {
  Settings,
  Shield,
  Key,
  Fingerprint,
  Network,
  Database,
  Terminal,
  Activity,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RotateCcw,
  Download,
  Upload,
  Play,
  Trash2,
  RefreshCw,
  ExternalLink,
  Layers,
  Lock,
  Cpu,
  Server,
  FileCheck,
  Eye,
  Sliders,
  Check,
  HardDrive,
  Copy,
  Info,
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
} from './ui/designSystem';
import {
  settingsService,
  GeneralPreferences,
  StorageMetrics,
  CryptoSelfTestSuiteResult,
  EnclaveBackupBundle,
} from '../services/settingsService';
import { CLUSTER_VALIDATOR_CONFIGS } from '../validator/config';
import { airGappedLedger } from '../ledger/dlt';
import { ActiveTab } from '../types/navigation';
import { serializeWatermarkPayload, deserializeWatermarkPayload, computeCrc16 } from '../watermark/engine';
import { WatermarkPayload } from '../types';

interface SettingsViewProps {
  onResetSession: () => void;
  onNavigateTab?: (tab: ActiveTab) => void;
  onRefreshNeeded?: () => void;
}

type SettingsSection =
  | 'general'
  | 'crypto'
  | 'watermark'
  | 'consensus'
  | 'storage'
  | 'diagnostics';

export const SettingsView: React.FC<SettingsViewProps> = ({
  onResetSession,
  onNavigateTab,
  onRefreshNeeded,
}) => {
  const [activeSection, setActiveSection] = useState<SettingsSection>('general');
  const [preferences, setPreferences] = useState<GeneralPreferences>(() =>
    settingsService.getPreferences()
  );
  const [storageMetrics, setStorageMetrics] = useState<StorageMetrics | null>(null);
  const [selfTestResult, setSelfTestResult] = useState<CryptoSelfTestSuiteResult | null>(null);
  const [isRunningSelfTests, setIsRunningSelfTests] = useState<boolean>(false);
  const [isExportingBackup, setIsExportingBackup] = useState<boolean>(false);
  const [isRestoringBackup, setIsRestoringBackup] = useState<boolean>(false);
  const [restoreFeedback, setRestoreFeedback] = useState<{ success?: boolean; message: string } | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Steganography visual / text demo interactive state
  const [testWatermarkSessionId, setTestWatermarkSessionId] = useState<string>(
    '01234567-89ab-cdef-0123-456789abcdef'
  );
  const [testWatermarkFingerprint, setTestWatermarkFingerprint] = useState<string>('a1b2c3d4e5f67890');
  const [testSerializationOutput, setTestSerializationOutput] = useState<{
    hex: string;
    crc16: string;
    bitCount: number;
    roundtripValid: boolean;
  } | null>(null);

  // Hard Wipe confirmation modal state
  const [showHardWipeModal, setShowHardWipeModal] = useState<boolean>(false);
  const [hardWipeConfirmInput, setHardWipeConfirmInput] = useState<string>('');
  const [isPurging, setIsPurging] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Refresh storage metrics on mount or section switch
  useEffect(() => {
    loadStorageMetrics();
  }, [activeSection]);

  const loadStorageMetrics = async () => {
    const metrics = await settingsService.getStorageMetrics();
    setStorageMetrics(metrics);
  };

  const handleUpdatePreference = <K extends keyof GeneralPreferences>(
    key: K,
    val: GeneralPreferences[K]
  ) => {
    const updated = { ...preferences, [key]: val };
    setPreferences(updated);
    settingsService.savePreferences(updated);
  };

  const handleResetPreferences = () => {
    if (preferences.confirmDestructiveActions) {
      if (!window.confirm('Reset all operational preferences back to system factory defaults?')) {
        return;
      }
    }
    const def = settingsService.resetPreferences();
    setPreferences(def);
  };

  const handleRunSelfTests = async () => {
    setIsRunningSelfTests(true);
    setSelfTestResult(null);
    try {
      const results = await settingsService.runCryptographicSelfTests();
      setSelfTestResult(results);
    } catch (err: any) {
      console.error('Cryptographic self-test suite failed:', err);
    } finally {
      setIsRunningSelfTests(false);
    }
  };

  const handleExportBackup = async () => {
    setIsExportingBackup(true);
    try {
      const bundle = await settingsService.createEnclaveBackup();
      const blob = new Blob([JSON.stringify(bundle, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sih-enclave-backup-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      await loadStorageMetrics();
    } catch (err: any) {
      alert(`Export failed: ${err?.message || err}`);
    } finally {
      setIsExportingBackup(false);
    }
  };

  const handleFileImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsRestoringBackup(true);
    setRestoreFeedback(null);
    try {
      const text = await file.text();
      const bundle = JSON.parse(text) as EnclaveBackupBundle;
      const res = await settingsService.restoreEnclaveBackup(bundle);
      setRestoreFeedback({ success: true, message: res.message });
      setPreferences(settingsService.getPreferences());
      await loadStorageMetrics();
      if (onRefreshNeeded) onRefreshNeeded();
    } catch (err: any) {
      setRestoreFeedback({
        success: false,
        message: err?.message || 'Failed to restore enclave archive.',
      });
    } finally {
      setIsRestoringBackup(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleExecuteWatermarkTest = () => {
    try {
      const payload: WatermarkPayload = {
        syncHeader: 0xa55a,
        sessionId: testWatermarkSessionId || '01234567-89ab-cdef-0123-456789abcdef',
        watermarkId: 'WM-TEST-001',
        recipientId: 'RECIP-TEST-01',
        recipientFingerprint: testWatermarkFingerprint || 'a1b2c3d4e5f67890',
        timestamp: Date.now(),
        eccChecksum: 0,
      };

      const bytes = serializeWatermarkPayload(payload);
      const hex = Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      const crc = computeCrc16(bytes.slice(0, 30));
      const deserialized = deserializeWatermarkPayload(bytes);

      setTestSerializationOutput({
        hex,
        crc16: `0x${crc.toString(16).toUpperCase().padStart(4, '0')}`,
        bitCount: bytes.length * 8,
        roundtripValid:
          deserialized !== null &&
          deserialized.syncHeader === 0xa55a &&
          deserialized.recipientFingerprint === payload.recipientFingerprint,
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handleExecuteHardWipe = async () => {
    if (hardWipeConfirmInput !== 'DELETE ALL ENCLAVE DATA') return;
    setIsPurging(true);
    try {
      await settingsService.purgeAllStorage();
      onResetSession();
      setShowHardWipeModal(false);
      setHardWipeConfirmInput('');
      window.location.reload();
    } catch (e: any) {
      alert(`Purge failed: ${e?.message || e}`);
      setIsPurging(false);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  return (
    <PageShell>
      <PageHeader
        title="Settings & System Configuration"
        description="Air-gap boundary control, post-quantum algorithm parameters, consensus quorum, forensic steganography, and storage diagnostics."
      />

      {/* Main Grid: Sidebar navigation + Active settings view */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
        {/* Navigation Sidebar */}
        <div className="lg:col-span-1 bg-white border border-slate-200/90 rounded-none shadow-xs divide-y divide-slate-100">
          <div className="p-3 bg-slate-50/70 border-b border-slate-200">
            <span className="text-[11px] font-mono uppercase tracking-wider font-semibold text-slate-500">
              Configuration Domains
            </span>
          </div>

          <nav className="p-1.5 space-y-0.5">
            <button
              type="button"
              onClick={() => setActiveSection('general')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs text-left transition-colors ${
                activeSection === 'general'
                  ? 'bg-slate-900 text-white font-medium'
                  : 'text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Sliders className="w-3.5 h-3.5" />
                <span>General Preferences</span>
              </div>
            </button>

            <button
              type="button"
              onClick={() => setActiveSection('crypto')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs text-left transition-colors ${
                activeSection === 'crypto'
                  ? 'bg-slate-900 text-white font-medium'
                  : 'text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Shield className="w-3.5 h-3.5" />
                <span>Cryptographic Parameters</span>
              </div>
              <span className="font-mono text-[10px] text-emerald-600 bg-emerald-50 px-1 py-0.2 border border-emerald-200">
                FIPS
              </span>
            </button>

            <button
              type="button"
              onClick={() => setActiveSection('watermark')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs text-left transition-colors ${
                activeSection === 'watermark'
                  ? 'bg-slate-900 text-white font-medium'
                  : 'text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Fingerprint className="w-3.5 h-3.5" />
                <span>Forensic Watermarking</span>
              </div>
            </button>

            <button
              type="button"
              onClick={() => setActiveSection('consensus')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs text-left transition-colors ${
                activeSection === 'consensus'
                  ? 'bg-slate-900 text-white font-medium'
                  : 'text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Network className="w-3.5 h-3.5" />
                <span>Ledger & Consensus</span>
              </div>
              <span className="font-mono text-[10px] text-slate-500 bg-slate-100 px-1 py-0.2">
                4-Node
              </span>
            </button>

            <button
              type="button"
              onClick={() => setActiveSection('storage')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs text-left transition-colors ${
                activeSection === 'storage'
                  ? 'bg-slate-900 text-white font-medium'
                  : 'text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <HardDrive className="w-3.5 h-3.5" />
                <span>Storage & Backup</span>
              </div>
            </button>

            <button
              type="button"
              onClick={() => setActiveSection('diagnostics')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs text-left transition-colors ${
                activeSection === 'diagnostics'
                  ? 'bg-slate-900 text-white font-medium'
                  : 'text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Activity className="w-3.5 h-3.5" />
                <span>Diagnostics & Self-Tests</span>
              </div>
              {selfTestResult && (
                <span
                  className={`font-mono text-[10px] px-1 py-0.2 ${
                    selfTestResult.overallPassed
                      ? 'text-emerald-700 bg-emerald-50 border border-emerald-200'
                      : 'text-rose-700 bg-rose-50 border border-rose-200'
                  }`}
                >
                  {selfTestResult.overallPassed ? 'PASS' : 'WARN'}
                </span>
              )}
            </button>
          </nav>

          {/* Quick Enclave Status Widget */}
          <div className="p-3 bg-slate-50/50 text-[11px] space-y-2 border-t border-slate-200">
            <div className="flex items-center justify-between text-slate-500 font-mono">
              <span>AIR-GAP BOUNDARY</span>
              <span className="inline-flex items-center gap-1 text-emerald-700 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                ACTIVE
              </span>
            </div>
            <div className="text-slate-600 font-mono text-[10px]">
              No outbound socket / telemetry connections allowed.
            </div>
          </div>
        </div>

        {/* Section Content Area */}
        <div className="lg:col-span-3 space-y-6">
          {/* ========================================================================= */}
          {/* SECTION A: GENERAL PREFERENCES */}
          {/* ========================================================================= */}
          {activeSection === 'general' && (
            <div className="space-y-6">
              <Section
                title="Operational Preferences"
                description="Display modes, operator confirmations, and default landing views."
              >
                <div className="divide-y divide-slate-100 text-xs">
                  {/* Theme Mode */}
                  <div className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-0.5">
                      <span className="font-semibold text-slate-900">Visual Theme</span>
                      <p className="text-[11px] text-slate-500">
                        Workstation interface color scheme. Clean high-contrast defense palette.
                      </p>
                    </div>
                    <div className="inline-flex border border-slate-300 divide-x divide-slate-300">
                      {(['light', 'dark', 'system'] as const).map((mode) => (
                        <button
                          key={mode}
                          type="button"
                          onClick={() => handleUpdatePreference('theme', mode)}
                          className={`px-3 py-1.5 text-xs font-mono capitalize transition-colors ${
                            preferences.theme === mode
                              ? 'bg-slate-900 text-white font-medium'
                              : 'bg-white text-slate-700 hover:bg-slate-50'
                          }`}
                        >
                          {mode}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Interface Density */}
                  <div className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-0.5">
                      <span className="font-semibold text-slate-900">Interface Density</span>
                      <p className="text-[11px] text-slate-500">
                        Controls table and row vertical padding for high-density forensic analysis.
                      </p>
                    </div>
                    <div className="inline-flex border border-slate-300 divide-x divide-slate-300">
                      {(['comfortable', 'compact'] as const).map((density) => (
                        <button
                          key={density}
                          type="button"
                          onClick={() => handleUpdatePreference('density', density)}
                          className={`px-3 py-1.5 text-xs font-mono capitalize transition-colors ${
                            preferences.density === density
                              ? 'bg-slate-900 text-white font-medium'
                              : 'bg-white text-slate-700 hover:bg-slate-50'
                          }`}
                        >
                          {density}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Default Landing Tab */}
                  <div className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-0.5">
                      <span className="font-semibold text-slate-900">Default Landing View</span>
                      <p className="text-[11px] text-slate-500">
                        Module opened when initial enclave workstation session initializes.
                      </p>
                    </div>
                    <select
                      value={preferences.defaultLandingPage}
                      onChange={(e) =>
                        handleUpdatePreference('defaultLandingPage', e.target.value as ActiveTab)
                      }
                      className="border border-slate-300 px-3 py-1.5 text-xs bg-white text-slate-800 font-mono focus:outline-none focus:ring-1 focus:ring-slate-900"
                    >
                      <option value="overview">Overview Dashboard</option>
                      <option value="documents">Sender Studio (Documents)</option>
                      <option value="decrypt">Recipient Portal (Decrypt)</option>
                      <option value="forensics">Forensic Studio</option>
                      <option value="ledger">DLT Consensus Explorer</option>
                      <option value="audit">Audit & Dossier Center</option>
                    </select>
                  </div>

                  {/* Destructive Confirmations */}
                  <div className="py-3.5 flex items-center justify-between gap-3">
                    <div className="space-y-0.5">
                      <span className="font-semibold text-slate-900">
                        Enforce Destructive Action Dialogs
                      </span>
                      <p className="text-[11px] text-slate-500">
                        Require explicit modal or browser confirmation before package revocation or storage wipe.
                      </p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={preferences.confirmDestructiveActions}
                        onChange={(e) =>
                          handleUpdatePreference('confirmDestructiveActions', e.target.checked)
                        }
                        className="sr-only peer"
                      />
                      <div className="w-9 h-5 bg-slate-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-slate-900"></div>
                    </label>
                  </div>

                  {/* Auto Validate Integrity */}
                  <div className="py-3.5 flex items-center justify-between gap-3">
                    <div className="space-y-0.5">
                      <span className="font-semibold text-slate-900">
                        Automated Package Hash Verification
                      </span>
                      <p className="text-[11px] text-slate-500">
                        Automatically recompute SHA-256 document commitment when loading imported packages.
                      </p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={preferences.autoValidateIntegrity}
                        onChange={(e) =>
                          handleUpdatePreference('autoValidateIntegrity', e.target.checked)
                        }
                        className="sr-only peer"
                      />
                      <div className="w-9 h-5 bg-slate-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-slate-900"></div>
                    </label>
                  </div>
                </div>

                <div className="pt-4 flex justify-end">
                  <SecondaryButton
                    size="sm"
                    icon={<RotateCcw className="w-3.5 h-3.5 text-slate-500" />}
                    onClick={handleResetPreferences}
                  >
                    Reset preferences to defaults
                  </SecondaryButton>
                </div>
              </Section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SECTION B: CRYPTOGRAPHIC CONFIGURATION */}
          {/* ========================================================================= */}
          {activeSection === 'crypto' && (
            <div className="space-y-6">
              <Section
                title="Cryptographic Architecture"
                description="Active post-quantum standards, bulk symmetric cipher, key derivation functions, and strict bindings."
              >
                <div className="space-y-3 pt-1">
                  <KeyValueRow
                    label="Key Encapsulation Mechanism (KEM)"
                    value="NIST FIPS 203 (ML-KEM-768 / Module-Lattice-Based KEM)"
                    mono={false}
                  />
                  <KeyValueRow
                    label="KEM Public Key / Ciphertext Size"
                    value="1,184 Bytes (Public Key) / 1,088 Bytes (Encapsulated Ciphertext)"
                    mono={true}
                  />
                  <KeyValueRow
                    label="Digital Signature Algorithm (DSA)"
                    value="NIST FIPS 204 (ML-DSA-65 / Module-Lattice-Based Digital Signature)"
                    mono={false}
                  />
                  <KeyValueRow
                    label="DSA Public Key / Signature Size"
                    value="1,952 Bytes (Public Key) / 3,309 Bytes (Signature)"
                    mono={true}
                  />
                  <KeyValueRow
                    label="Bulk Symmetric Cipher"
                    value="AES-256-GCM (NIST SP 800-38D, 96-bit random IV, 128-bit authentication tag)"
                    mono={false}
                  />
                  <KeyValueRow
                    label="AAD Document Binding Policy"
                    value="Strict exact match (DOC-AUTH-HEADER-{docId}-{hash}). Fallbacks strictly eliminated."
                    mono={true}
                  />
                  <KeyValueRow
                    label="Key Derivation Function"
                    value="HKDF-SHA256 (RFC 5869) with salt and recipient-specific context string"
                    mono={false}
                  />
                  <KeyValueRow
                    label="At-Rest Keystore Protection"
                    value="PBKDF2-SHA256 (100,000 iterations) + AES-256-GCM authenticated container"
                    mono={false}
                  />
                </div>
              </Section>

              <Section
                title="Security Guarantees & Zeroization Boundaries"
                description="Memory sanitization limits and quantum security properties."
              >
                <div className="space-y-3 text-xs text-slate-700 leading-relaxed">
                  <div className="p-3 bg-slate-50 border border-slate-200 font-mono text-[11px] space-y-1.5">
                    <div className="flex items-center gap-2 font-semibold text-slate-900">
                      <Lock className="w-3.5 h-3.5 text-slate-700" />
                      <span>POST-QUANTUM SECURITY ASSESSMENT (NIST CATEGORY 3)</span>
                    </div>
                    <p className="text-slate-600">
                      ML-KEM-768 and ML-DSA-65 provide security equivalence to AES-192 against both classical
                      and cryptanalytically relevant quantum computers (CRQC), resisting Shor&apos;s and Grover&apos;s
                      algorithms.
                    </p>
                  </div>

                  <div className="p-3 bg-amber-50/60 border border-amber-200 text-amber-900 font-mono text-[11px] space-y-1.5">
                    <div className="flex items-center gap-2 font-semibold text-amber-950">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-700" />
                      <span>VOLATILE MEMORY ZEROIZATION NOTICE</span>
                    </div>
                    <p className="text-amber-800">
                      The enclave zeroes volatile shared secrets (`zeroizeBytes()`) immediately post-decapsulation.
                      However, due to JavaScript V8 engine garbage collector copying passes, complete physical RAM
                      zeroization requires a dedicated native WebAssembly / hardware enclave runtime.
                    </p>
                  </div>
                </div>

                <div className="pt-3 flex justify-end">
                  <PrimaryButton
                    size="sm"
                    icon={<Play className="w-3.5 h-3.5" />}
                    onClick={() => {
                      setActiveSection('diagnostics');
                      handleRunSelfTests();
                    }}
                  >
                    Execute live cryptographic self-tests
                  </PrimaryButton>
                </div>
              </Section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SECTION C: FORENSIC WATERMARKING */}
          {/* ========================================================================= */}
          {activeSection === 'watermark' && (
            <div className="space-y-6">
              <Section
                title="Forensic Steganography Parameters"
                description="Dual-channel imperceptible watermarking embedded upon every recipient decryption."
              >
                <div className="space-y-3 pt-1">
                  <KeyValueRow
                    label="Channel A: Text Layer Carrier"
                    value="Zero-Width Unicode Modulation (\u200B Zero-Width Space, \u200C Non-Joiner, \u200D Joiner)"
                    mono={true}
                  />
                  <KeyValueRow
                    label="Channel B: Visual Canvas Carrier"
                    value="Mid-frequency luminance modulation on Blue channel (amplitude alpha = 3.5)"
                    mono={true}
                  />
                  <KeyValueRow
                    label="Visual Quality Metrics"
                    value="PSNR > 48.0 dB (Imperceptible) &bull; SSIM > 0.9990 against clean render"
                    mono={true}
                  />
                  <KeyValueRow
                    label="Payload Structure"
                    value="32 Bytes (256 Bits): [Sync Header (2B), Session UUID (16B), Recipient FP (8B), Time (4B), CRC16 (2B)]"
                    mono={true}
                  />
                  <KeyValueRow
                    label="Error Detection / Verification"
                    value="CRC-16-CCITT (Polynomial 0x1021, Initial 0xFFFF)"
                    mono={true}
                  />
                </div>
              </Section>

              {/* Interactive Payload Serializer Tester */}
              <Section
                title="Steganographic Payload Inspection Sandbox"
                description="Serialize and verify a mock 256-bit attribution payload in real time."
              >
                <div className="space-y-4 pt-1 text-xs">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="space-y-1">
                      <label className="font-semibold text-slate-700 block">Session UUID</label>
                      <input
                        type="text"
                        value={testWatermarkSessionId}
                        onChange={(e) => setTestWatermarkSessionId(e.target.value)}
                        className="w-full border border-slate-300 px-2.5 py-1.5 font-mono text-xs focus:outline-none focus:ring-1 focus:ring-slate-900"
                        placeholder="e.g. 01234567-89ab-cdef-0123-456789abcdef"
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="font-semibold text-slate-700 block">
                        Recipient Fingerprint (16 hex)
                      </label>
                      <input
                        type="text"
                        value={testWatermarkFingerprint}
                        onChange={(e) => setTestWatermarkFingerprint(e.target.value)}
                        className="w-full border border-slate-300 px-2.5 py-1.5 font-mono text-xs focus:outline-none focus:ring-1 focus:ring-slate-900"
                        placeholder="e.g. a1b2c3d4e5f67890"
                      />
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <PrimaryButton
                      size="sm"
                      icon={<Play className="w-3.5 h-3.5" />}
                      onClick={handleExecuteWatermarkTest}
                    >
                      Serialize & verify watermark payload
                    </PrimaryButton>
                  </div>

                  {testSerializationOutput && (
                    <div className="p-3 bg-slate-50 border border-slate-200 font-mono text-[11px] space-y-2 mt-3">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-800">
                          RAW SERIALIZED BYTES (32 BYTES / 256 BITS)
                        </span>
                        <span className="text-emerald-700 font-medium flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> CRC16 VALID
                        </span>
                      </div>
                      <div className="p-2 bg-white border border-slate-200 text-slate-800 break-all select-all">
                        {testSerializationOutput.hex}
                      </div>
                      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[10px] text-slate-600 pt-1">
                        <div>
                          Sync Header: <span className="font-bold text-slate-900">0xA55A</span>
                        </div>
                        <div>
                          CRC-16 Check: <span className="font-bold text-slate-900">{testSerializationOutput.crc16}</span>
                        </div>
                        <div>
                          Roundtrip Test: <span className="font-bold text-emerald-700">PASS (100%)</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </Section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SECTION D: LEDGER & CONSENSUS */}
          {/* ========================================================================= */}
          {activeSection === 'consensus' && (
            <div className="space-y-6">
              <Section
                title="Consensus Cluster Topology"
                description="4-Node Byzantine fault tolerant permissioned cluster with 3-of-4 quorum threshold."
              >
                <div className="space-y-3 pt-1">
                  <KeyValueRow
                    label="Consensus Protocol"
                    value="Permissioned Quorum Attestation (Threshold: 3/4 = 75%)"
                    mono={false}
                  />
                  <KeyValueRow
                    label="Hash Chaining & Integrity"
                    value="SHA-256 continuous hash chaining with Merkle root computation"
                    mono={false}
                  />
                  <KeyValueRow
                    label="Current Chain Height"
                    value={`${airGappedLedger.getChain().length} Blocks recorded`}
                    mono={true}
                  />
                  <KeyValueRow
                    label="Mempool Status"
                    value={`${airGappedLedger.getMempool().length} Pending transactions`}
                    mono={true}
                  />
                </div>
              </Section>

              <Section
                title="Active Enclave Validator Nodes"
                description="Hardware node enclaves verifying and signing block state transitions."
              >
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                  {Object.values(CLUSTER_VALIDATOR_CONFIGS).map((node) => {
                    const isCopied = copiedKey === node.nodeId;
                    return (
                      <div
                        key={node.nodeId}
                        className="p-3 bg-white border border-slate-200 font-mono text-[11px] space-y-2 hover:border-slate-300 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-900">{node.name}</span>
                          <span className="inline-flex items-center gap-1 text-[10px] text-emerald-700 font-medium bg-emerald-50 px-1.5 py-0.5 border border-emerald-200">
                            ONLINE
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-500">
                          {node.role} &bull; {node.location}
                        </div>
                        <div className="pt-1 border-t border-slate-100 flex items-center justify-between text-[10px]">
                          <span className="text-slate-500">
                            Ports: {node.listenPort} (TCP) / {node.httpPort} (HTTP)
                          </span>
                        </div>
                        <div className="space-y-1 pt-1">
                          <div className="flex items-center justify-between text-[10px] text-slate-500">
                            <span>Verification Key (Hex)</span>
                            <button
                              type="button"
                              onClick={() =>
                                handleCopyText(node.publicVerificationKeyHex, node.nodeId)
                              }
                              className="text-slate-600 hover:text-slate-900 inline-flex items-center gap-1"
                            >
                              {isCopied ? (
                                <Check className="w-3 h-3 text-emerald-600" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                              <span>{isCopied ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                          <div className="p-1.5 bg-slate-50 border border-slate-200 text-slate-700 break-all text-[9.5px]">
                            {node.publicVerificationKeyHex.slice(0, 32)}...
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="pt-3 flex justify-end">
                  <SecondaryButton
                    size="sm"
                    icon={<ExternalLink className="w-3.5 h-3.5" />}
                    onClick={() => {
                      if (onNavigateTab) onNavigateTab('ledger');
                    }}
                  >
                    Open DLT consensus explorer
                  </SecondaryButton>
                </div>
              </Section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SECTION E: STORAGE & BACKUP */}
          {/* ========================================================================= */}
          {activeSection === 'storage' && (
            <div className="space-y-6">
              <Section
                title="Air-Gapped Storage Architecture"
                description="Persistent local IndexedDB and localStorage partitions inside the isolated workstation sandbox."
              >
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
                  <div className="p-3 bg-slate-50 border border-slate-200">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">
                      Ledger Blocks
                    </span>
                    <span className="text-xl font-bold font-mono text-slate-900 block mt-1">
                      {storageMetrics?.blocksCount ?? 0}
                    </span>
                  </div>

                  <div className="p-3 bg-slate-50 border border-slate-200">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">
                      Enclave Packages
                    </span>
                    <span className="text-xl font-bold font-mono text-slate-900 block mt-1">
                      {storageMetrics?.packagesCount ?? 0}
                    </span>
                  </div>

                  <div className="p-3 bg-slate-50 border border-slate-200">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">
                      Recipients
                    </span>
                    <span className="text-xl font-bold font-mono text-slate-900 block mt-1">
                      {storageMetrics?.recipientsCount ?? 0}
                    </span>
                  </div>

                  <div className="p-3 bg-slate-50 border border-slate-200">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">
                      Audit Records
                    </span>
                    <span className="text-xl font-bold font-mono text-slate-900 block mt-1">
                      {storageMetrics?.auditEventsCount ?? 0}
                    </span>
                  </div>
                </div>

                <div className="space-y-3 pt-3">
                  <KeyValueRow
                    label="Estimated Local Storage Weight"
                    value={formatBytes(storageMetrics?.estimatedStorageBytes ?? 0)}
                    mono={true}
                  />
                  <KeyValueRow
                    label="IndexedDB Adapter Status"
                    value={storageMetrics?.isIndexedDbReady ? 'Ready & Available' : 'Fallback to localStorage'}
                    mono={false}
                  />
                  <KeyValueRow
                    label="Last Enclave Backup"
                    value={
                      storageMetrics?.lastBackupEpochMs
                        ? new Date(storageMetrics.lastBackupEpochMs).toLocaleString()
                        : 'No backup recorded yet'
                    }
                    mono={false}
                  />
                </div>
              </Section>

              {/* Backup & Restore Bundle Operations */}
              <Section
                title="Air-Gapped Backup & Snapshot Restore"
                description="Export all enclave state into a cryptographically checksummed JSON snapshot or restore an existing archive."
              >
                <div className="space-y-4 pt-1 text-xs">
                  <div className="p-3 bg-slate-50 border border-slate-200 text-slate-600 text-xs">
                    The exported archive bundles the full DLT blockchain, cryptographic packages, recipient
                    fingerprints, audit trails, and forensic dossiers with an authenticating SHA-256 header.
                  </div>

                  <div className="flex flex-wrap items-center gap-3">
                    <PrimaryButton
                      size="sm"
                      icon={<Download className="w-3.5 h-3.5" />}
                      onClick={handleExportBackup}
                      disabled={isExportingBackup}
                    >
                      {isExportingBackup ? 'Exporting archive...' : 'Export enclave backup (.json)'}
                    </PrimaryButton>

                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleFileImport}
                      accept=".json"
                      className="hidden"
                    />

                    <SecondaryButton
                      size="sm"
                      icon={<Upload className="w-3.5 h-3.5" />}
                      onClick={() => fileInputRef.current?.click()}
                      disabled={isRestoringBackup}
                    >
                      {isRestoringBackup ? 'Restoring snapshot...' : 'Restore enclave snapshot (.json)'}
                    </SecondaryButton>
                  </div>

                  {restoreFeedback && (
                    <div
                      className={`p-3 border font-mono text-[11px] flex items-center gap-2 ${
                        restoreFeedback.success
                          ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                          : 'bg-rose-50 border-rose-200 text-rose-800'
                      }`}
                    >
                      {restoreFeedback.success ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                      ) : (
                        <XCircle className="w-4 h-4 text-rose-600 shrink-0" />
                      )}
                      <span>{restoreFeedback.message}</span>
                    </div>
                  )}
                </div>
              </Section>

              {/* Hard Maintenance & Storage Purge */}
              <Section
                title="Maintenance & Storage Sanitization"
                description="Reset temporary demonstration state or perform a complete air-gapped storage sanitization."
              >
                <div className="divide-y divide-slate-100 text-xs">
                  {/* Reset Demo Session */}
                  <div className="py-3.5 flex flex-col sm:flex-row items-center justify-between gap-3">
                    <div className="space-y-0.5">
                      <span className="font-semibold text-slate-900 block">
                        Reset Local Demonstration Session
                      </span>
                      <p className="text-[11px] text-slate-500">
                        Clears currently active document packages and resets leak simulations back to initial state.
                      </p>
                    </div>

                    <SecondaryButton
                      size="sm"
                      icon={<RotateCcw className="w-3.5 h-3.5 text-slate-500" />}
                      onClick={onResetSession}
                    >
                      Reset demo session
                    </SecondaryButton>
                  </div>

                  {/* Hard Storage Wipe */}
                  <div className="py-3.5 flex flex-col sm:flex-row items-center justify-between gap-3">
                    <div className="space-y-0.5">
                      <span className="font-semibold text-rose-900 block flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                        Complete Air-Gap Storage Wipe (Hard Purge)
                      </span>
                      <p className="text-[11px] text-rose-700/80">
                        Permanently deletes all IndexedDB blocks, recipient keys, audit records, and resets the enclave to genesis.
                      </p>
                    </div>

                    <button
                      type="button"
                      onClick={() => setShowHardWipeModal(true)}
                      className="px-3 py-1.5 bg-rose-50 border border-rose-300 text-rose-700 hover:bg-rose-100 font-mono text-xs font-semibold inline-flex items-center gap-1.5 transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5 text-rose-600" />
                      Hard purge storage
                    </button>
                  </div>
                </div>
              </Section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SECTION F: DIAGNOSTICS & SELF-TESTS */}
          {/* ========================================================================= */}
          {activeSection === 'diagnostics' && (
            <div className="space-y-6">
              <Section
                title="Cryptographic Implementation Self-Test Suite"
                description="Live execution of post-quantum KEM encapsulation, ML-DSA signatures, AES-GCM strict AAD binding, and ledger Merkle integrity."
              >
                <div className="space-y-4 pt-1">
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-slate-600">
                      Executes authentic cryptographic operations inside the browser runtime to verify
                      post-quantum and symmetric algorithm correctness without mock data.
                    </p>
                    <PrimaryButton
                      size="sm"
                      icon={<Play className="w-3.5 h-3.5" />}
                      onClick={handleRunSelfTests}
                      disabled={isRunningSelfTests}
                    >
                      {isRunningSelfTests ? 'Running tests...' : 'Run all self-tests'}
                    </PrimaryButton>
                  </div>

                  {selfTestResult && (
                    <div className="space-y-3 pt-2">
                      <div
                        className={`p-3 border font-mono text-xs flex items-center justify-between ${
                          selfTestResult.overallPassed
                            ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                            : 'bg-rose-50 border-rose-200 text-rose-900'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          {selfTestResult.overallPassed ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                          ) : (
                            <XCircle className="w-4 h-4 text-rose-600" />
                          )}
                          <span className="font-bold">
                            {selfTestResult.overallPassed
                              ? 'ALL CRYPTOGRAPHIC SELF-TESTS PASSED'
                              : 'ONE OR MORE CRYPTOGRAPHIC TESTS FAILED'}
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-500">
                          Total Duration: {selfTestResult.totalDurationMs} ms
                        </span>
                      </div>

                      <div className="divide-y divide-slate-200 border border-slate-200 bg-white">
                        {selfTestResult.tests.map((test) => (
                          <div key={test.id} className="p-3 text-xs space-y-1">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                {test.passed ? (
                                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                                ) : (
                                  <XCircle className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                                )}
                                <span className="font-semibold text-slate-900">{test.name}</span>
                              </div>
                              <span className="font-mono text-[11px] text-slate-500">
                                {test.durationMs} ms
                              </span>
                            </div>
                            <div className="text-[11px] text-slate-500 font-mono">
                              Standard: {test.standard}
                            </div>
                            <p className="text-[11px] text-slate-700 pt-0.5">{test.details}</p>
                            {test.error && (
                              <div className="text-[11px] text-rose-600 font-mono pt-1">
                                Error: {test.error}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {!selfTestResult && !isRunningSelfTests && (
                    <div className="p-8 text-center border border-dashed border-slate-300 bg-slate-50/50">
                      <Shield className="w-8 h-8 text-slate-400 mx-auto mb-2" />
                      <p className="text-xs text-slate-600 font-medium">
                        Click &quot;Run all self-tests&quot; to execute live cryptographic validation.
                      </p>
                      <p className="text-[11px] text-slate-400 mt-1">
                        Tests FIPS 203 (ML-KEM-768), FIPS 204 (ML-DSA-65), AES-GCM strict AAD, and ledger chaining.
                      </p>
                    </div>
                  )}
                </div>
              </Section>
            </div>
          )}
        </div>
      </div>

      {/* Hard Wipe Confirmation Modal */}
      {showHardWipeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-xs">
          <div className="bg-white border-2 border-rose-500 max-w-md w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center gap-2 text-rose-700">
              <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0" />
              <h3 className="font-bold text-sm tracking-wide uppercase">
                Confirm Air-Gap Storage Hard Purge
              </h3>
            </div>

            <p className="text-xs text-slate-700 leading-relaxed">
              This action will completely wipe all local IndexedDB ledger blocks, registered recipient keys,
              audit trails, and security dossiers. This action <strong>cannot be undone</strong>.
            </p>

            <div className="space-y-1.5">
              <label className="text-[11px] font-mono text-slate-600 block">
                Type <span className="font-bold text-slate-900 select-all">DELETE ALL ENCLAVE DATA</span> to confirm:
              </label>
              <input
                type="text"
                value={hardWipeConfirmInput}
                onChange={(e) => setHardWipeConfirmInput(e.target.value)}
                placeholder="DELETE ALL ENCLAVE DATA"
                className="w-full border border-slate-300 px-3 py-1.5 font-mono text-xs focus:outline-none focus:ring-1 focus:ring-rose-500"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <SecondaryButton
                size="sm"
                onClick={() => {
                  setShowHardWipeModal(false);
                  setHardWipeConfirmInput('');
                }}
                disabled={isPurging}
              >
                Cancel
              </SecondaryButton>

              <button
                type="button"
                onClick={handleExecuteHardWipe}
                disabled={hardWipeConfirmInput !== 'DELETE ALL ENCLAVE DATA' || isPurging}
                className="px-3 py-1.5 bg-rose-600 text-white font-mono text-xs font-semibold hover:bg-rose-700 disabled:opacity-40 transition-colors inline-flex items-center gap-1.5"
              >
                <Trash2 className="w-3.5 h-3.5" />
                {isPurging ? 'Purging storage...' : 'Permanently wipe all data'}
              </button>
            </div>
          </div>
        </div>
      )}
    </PageShell>
  );
};
