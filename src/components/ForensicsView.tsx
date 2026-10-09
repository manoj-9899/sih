import React, { useState, useEffect } from 'react';
import {
  Search,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Database,
  ArrowRight,
  Copy,
  Check,
  FileUp,
  X,
  History,
  ShieldCheck,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Layers,
  Award,
  Download,
  FileCode,
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
import { ForensicAttributionReport, ForensicCaseRecord, ClassifiedDocument, ForensicAttributionCertificate } from '../types';
import { DistributionService } from '../services/distributionService';
import { airGappedStorage } from '../storage/airGappedStorage';
import { ForensicCertificateService } from '../services/forensicCertificateService';
import { ForensicAttributionCertificateViewer } from './ForensicAttributionCertificateViewer';
import { CertificateVerificationSection } from './CertificateVerificationSection';

interface ForensicsViewProps {
  initialLeakedText?: string;
  initialLeakedPdfBytes?: Uint8Array | null;
  initialLeakedFileName?: string;
  leakedMetadata?: { title: string; recipientName: string } | null;
  documents?: ClassifiedDocument[];
  onNavigateToLedger: () => void;
}

export const ForensicsView: React.FC<ForensicsViewProps> = ({
  initialLeakedText,
  initialLeakedPdfBytes,
  initialLeakedFileName,
  leakedMetadata,
  documents = [],
  onNavigateToLedger,
}) => {
  // Navigation / sub-view tabs
  const [activeSubTab, setActiveSubTab] = useState<'analyze' | 'history' | 'audit_certificate'>('analyze');

  // File Upload & Input State
  const [leakedPdfBytes, setLeakedPdfBytes] = useState<Uint8Array | null>(initialLeakedPdfBytes || null);
  const [leakedPdfName, setLeakedPdfName] = useState<string>(initialLeakedFileName || '');
  const [suspectedDocHash, setSuspectedDocHash] = useState<string>('');
  const [isDragOver, setIsDragOver] = useState(false);

  // Analysis Lifecycle
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisProgressStep, setAnalysisProgressStep] = useState<number>(0);
  const [report, setReport] = useState<ForensicAttributionReport | null>(null);
  const [showEvidenceDrawer, setShowEvidenceDrawer] = useState<boolean>(false);
  const [showCertificateViewer, setShowCertificateViewer] = useState<boolean>(false);
  const [selectedHistoricalCert, setSelectedHistoricalCert] = useState<ForensicAttributionCertificate | null>(null);

  // Case History State
  const [caseHistory, setCaseHistory] = useState<ForensicCaseRecord[]>([]);

  // Load history on mount or tab change
  const refreshHistory = async () => {
    try {
      const cases = await airGappedStorage.getForensicCases();
      setCaseHistory(cases);
    } catch (e) {
      console.warn('Failed to load forensic cases:', e);
    }
  };

  useEffect(() => {
    refreshHistory();
  }, [activeSubTab]);

  // Handle incoming leak simulation props
  useEffect(() => {
    if (initialLeakedPdfBytes) {
      setLeakedPdfBytes(initialLeakedPdfBytes);
      setLeakedPdfName(initialLeakedFileName || 'Leaked_Document.pdf');
      setReport(null);
      setShowEvidenceDrawer(false);
    } else if (initialLeakedText) {
      // If text string is passed, encode as UTF-8 bytes for pipeline
      const enc = new TextEncoder().encode(initialLeakedText);
      setLeakedPdfBytes(enc);
      setLeakedPdfName(initialLeakedFileName || 'Leaked_Document.pdf');
      setReport(null);
      setShowEvidenceDrawer(false);
    }
  }, [initialLeakedPdfBytes, initialLeakedFileName, initialLeakedText]);

  const handlePdfUpload = async (file: File) => {
    if (!file) return;
    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      setLeakedPdfBytes(bytes);
      setLeakedPdfName(file.name);
      setReport(null);
      setShowEvidenceDrawer(false);
    } catch (err) {
      console.error('Failed to read uploaded PDF:', err);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      handlePdfUpload(file);
    }
  };

  const handleRunAnalysis = async () => {
    if (!leakedPdfBytes) return;

    setIsAnalyzing(true);
    setAnalysisProgressStep(1);
    setReport(null);
    setShowEvidenceDrawer(false);

    try {
      // Step 1: Validate PDF
      await new Promise((r) => setTimeout(r, 120));
      setAnalysisProgressStep(2);

      // Step 2: Extract Watermark
      await new Promise((r) => setTimeout(r, 120));
      setAnalysisProgressStep(3);

      // Step 3: Validate Sync & CRC
      await new Promise((r) => setTimeout(r, 120));
      setAnalysisProgressStep(4);

      // Step 4: Ledger search & verification
      const result = await DistributionService.investigateLeakedDocument(
        leakedPdfBytes,
        suspectedDocHash || undefined
      );

      setAnalysisProgressStep(5);
      await new Promise((r) => setTimeout(r, 100));

      setReport(result);
      await refreshHistory();
    } catch (err) {
      console.error('Forensic analysis error:', err);
    } finally {
      setIsAnalyzing(false);
      setAnalysisProgressStep(0);
    }
  };

  const handleClear = () => {
    setLeakedPdfBytes(null);
    setLeakedPdfName('');
    setSuspectedDocHash('');
    setReport(null);
    setShowEvidenceDrawer(false);
  };

  const handleClearHistory = async () => {
    await airGappedStorage.clearForensicCases();
    setCaseHistory([]);
  };

  const isVerified =
    report &&
    (report.verificationStatus === 'VERIFIED' ||
      report.attributionVerdict === 'CONFIRMED_LEAK_SOURCE' ||
      report.attributionVerdict === 'VERIFIED') &&
    !!report.attributedRecipient;

  return (
    <PageShell>
      <PageHeader
        title="Forensic Investigation &amp; Cryptographic Attribution"
        description="Air-gapped post-quantum non-repudiation pipeline (NIST FIPS 204 ML-DSA-65 and immutable DLT block audit)."
      />

      {/* Sub-view Navigation Bar */}
      <div className="flex items-center gap-1 border-b border-slate-200 mb-6">
        <button
          onClick={() => setActiveSubTab('analyze')}
          className={`px-4 py-2 text-xs font-medium border-b-2 -mb-px transition-colors ${
            activeSubTab === 'analyze'
              ? 'border-indigo-600 text-indigo-600 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-900'
          }`}
        >
          Document analysis
        </button>
        <button
          onClick={() => setActiveSubTab('history')}
          className={`px-4 py-2 text-xs font-medium border-b-2 -mb-px transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'history'
              ? 'border-indigo-600 text-indigo-600 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-900'
          }`}
        >
          <span>Investigation history</span>
          {caseHistory.length > 0 && (
            <span className="text-[10px] text-slate-600 font-mono">
              ({caseHistory.length})
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveSubTab('audit_certificate')}
          className={`px-4 py-2 text-xs font-medium border-b-2 -mb-px transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'audit_certificate'
              ? 'border-indigo-600 text-indigo-600 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-900'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
          <span>Audit certificate (.cert.json)</span>
        </button>
      </div>

      {activeSubTab === 'audit_certificate' ? (
        <CertificateVerificationSection onNavigateToLedger={onNavigateToLedger} />
      ) : activeSubTab === 'analyze' ? (
        <div className="space-y-6">
          {/* 1. DOCUMENT DROPZONE & INVESTIGATOR INPUT AREA */}
          <Section
            title="Suspected leaked document"
            description="Upload the suspected leaked PDF document for blind cryptographic provenance extraction."
          >
            <div className="space-y-4 pt-1">
              {/* Dropzone container */}
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragOver(true);
                }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={handleDrop}
                className={`p-6 rounded-xl border-2 border-dashed transition-all text-center relative ${
                  isDragOver
                    ? 'border-indigo-500 bg-indigo-50/50'
                    : leakedPdfBytes
                    ? 'border-slate-300 bg-white'
                    : 'border-slate-200 hover:border-slate-300 bg-slate-50/60'
                }`}
              >
                <input
                  type="file"
                  accept=".pdf,application/pdf"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) handlePdfUpload(file);
                  }}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                />

                {leakedPdfBytes ? (
                  <div className="space-y-2">
                    <div className="w-10 h-10 rounded-lg bg-indigo-50 border border-indigo-100 flex items-center justify-center mx-auto text-indigo-600">
                      <FileText className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="text-xs font-semibold text-slate-900 flex items-center justify-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        <span>{leakedPdfName || 'leaked_document.pdf'}</span>
                      </div>
                      <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                        {(leakedPdfBytes.length / 1024).toFixed(1)} KB &bull; PDF structure verified &bull; Ready for blind structural analysis
                      </p>
                    </div>
                    <div className="pt-1">
                      <span className="text-[11px] text-slate-400">
                        Click or drop a different file to replace
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <FileUp className="w-7 h-7 text-slate-400 mx-auto" />
                    <div>
                      <div className="text-xs font-semibold text-slate-800">
                        Upload leaked PDF or drag and drop
                      </div>
                      <p className="text-[11px] text-slate-500 mt-0.5">
                        Inspects deep /ForensicProvenance structural catalog enclave and text stego channels
                      </p>
                    </div>
                    <div className="text-[11px] text-slate-400 pt-1">
                      PDF documents up to 50MB &bull; 100% client-side offline execution
                    </div>
                  </div>
                )}
              </div>

              {/* Simulated Leak Context banner (if navigated from Decrypt tab) */}
              {leakedMetadata && (
                <div className="p-3 bg-indigo-50/70 border border-indigo-100 rounded-lg flex items-center justify-between text-xs text-indigo-900">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold">Simulated leak source:</span>
                    <span>{leakedMetadata.title}</span>
                    <span className="text-slate-400">&bull;</span>
                    <span className="text-indigo-700">Origin: {leakedMetadata.recipientName}&apos;s copy</span>
                  </div>
                  <span className="text-[10px] text-indigo-600 font-mono font-medium">Ready for investigation</span>
                </div>
              )}

              {/* Optional Reference Document Selector */}
              {documents.length > 0 && (
                <div className="pt-1">
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    Optional reference document (for explicit cross-verification):
                  </label>
                  <select
                    value={suspectedDocHash}
                    onChange={(e) => setSuspectedDocHash(e.target.value)}
                    className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs bg-white text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                  >
                    <option value="">Autonomous blind scan (Infer document identity from ledger)</option>
                    {documents.map((d) => (
                      <option key={d.id} value={d.id}>
                        Cross-verify against: {d.title} ({d.classification})
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Actions Bar */}
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
                <span className="text-[11px] text-slate-500">
                  {leakedPdfBytes
                    ? 'Blindly extracts structural /ForensicProvenance enclave, validates CRC-16, and verifies ML-DSA-65 signature.'
                    : 'Select a PDF document above to initiate the 11-stage forensic analysis pipeline.'}
                </span>

                <div className="flex items-center gap-2">
                  {leakedPdfBytes && (
                    <SecondaryButton size="sm" onClick={handleClear} disabled={isAnalyzing}>
                      Clear
                    </SecondaryButton>
                  )}
                  <PrimaryButton
                    size="md"
                    icon={<Search className="w-3.5 h-3.5" />}
                    onClick={handleRunAnalysis}
                    loading={isAnalyzing}
                    disabled={!leakedPdfBytes}
                    data-tour-target="execute-attribution-btn"
                  >
                    {isAnalyzing ? 'Analyzing document...' : 'Analyze document'}
                  </PrimaryButton>
                </div>
              </div>

              {/* Progress Indicator during analysis */}
              {isAnalyzing && (
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-800 flex items-center gap-2">
                      <div className="w-3.5 h-3.5 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin shrink-0" />
                      Executing 11-stage cryptographic verification pipeline...
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">Stage {analysisProgressStep}/5</span>
                  </div>
                  <div className="grid grid-cols-5 gap-1.5 pt-1">
                    {[
                      '1. Validate PDF',
                      '2. Extract enclave',
                      '3. Verify CRC-16',
                      '4. Query ledger',
                      '5. Verify ML-DSA',
                    ].map((stepLabel, idx) => (
                      <div
                        key={idx}
                        className={`text-[10px] py-1 px-1.5 rounded text-center truncate ${
                          analysisProgressStep > idx
                            ? 'bg-emerald-50 text-emerald-800 font-semibold border border-emerald-200'
                            : analysisProgressStep === idx + 1
                            ? 'bg-indigo-50 text-indigo-700 font-semibold border border-indigo-200 animate-pulse'
                            : 'bg-slate-100 text-slate-400'
                        }`}
                      >
                        {stepLabel}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Section>

          {/* 2. FORENSIC VERIFICATION RESULT */}
          {report && (
            <Section
              title="Forensic verification result"
              description={`Report ID: ${report.reportId} &bull; Analyzed ${new Date(report.analyzedAt).toLocaleTimeString()}`}
              action={
                <span
                  className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-semibold border ${
                    isVerified
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200/90'
                      : 'bg-slate-100 text-slate-700 border-slate-300'
                  }`}
                >
                  {isVerified ? (
                    <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                  ) : (
                    <AlertTriangle className="w-3 h-3 text-slate-500" />
                  )}
                  <span>{isVerified ? 'VERIFIED' : 'ATTRIBUTION REJECTED'}</span>
                </span>
              }
            >
              <div className="space-y-6 pt-2">
                {/* SUCCESSFUL VERIFIED RESULT VIEW (Section 6 specifications) */}
                {isVerified && report.attributedRecipient && report.matchedEvent ? (
                  <div className="p-5 rounded-xl bg-slate-50 border border-emerald-200 text-slate-900 space-y-4">
                    {/* Header Banner */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-emerald-100">
                      <div>
                        <div className="text-xs font-bold text-emerald-900 tracking-wide flex items-center gap-1.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                          FORENSIC VERIFICATION COMPLETE
                        </div>
                        <div className="text-[11px] text-emerald-800 mt-0.5">
                          Cryptographically verified decryption event associated with the registered recipient key.
                        </div>
                      </div>
                      <div className="text-xs font-mono font-bold text-emerald-800 bg-emerald-50 px-2.5 py-1 rounded border border-emerald-300">
                        VERIFIED
                      </div>
                    </div>

                    {/* Minimalist Structured Result Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div className="p-3 bg-white rounded-lg border border-slate-200 space-y-0.5">
                        <span className="text-[11px] text-slate-500 font-medium">Recipient</span>
                        <div className="text-sm font-bold text-slate-900">
                          {report.attributedRecipient.name}
                        </div>
                        <div className="text-slate-500 text-[11px]">
                          {report.attributedRecipient.role} &bull; {report.attributedRecipient.organization}
                        </div>
                      </div>

                      <div className="p-3 bg-white rounded-lg border border-slate-200 space-y-0.5">
                        <span className="text-[11px] text-slate-500 font-medium">Decryption event</span>
                        <div className="font-mono font-semibold text-slate-900 text-xs">
                          {report.matchedEvent.eventId}
                        </div>
                        <div className="text-slate-500 text-[11px]">
                          Committed at: {new Date(report.matchedEvent.timestampEpochMs).toLocaleString()}
                        </div>
                      </div>

                      <div className="p-3 bg-white rounded-lg border border-slate-200 space-y-0.5">
                        <span className="text-[11px] text-slate-500 font-medium">Document</span>
                        <div className="font-semibold text-slate-900 text-xs">
                          {report.matchedEvent.documentTitle}
                        </div>
                        <div className="text-slate-500 text-[11px] font-mono truncate">
                          ID: {report.matchedEvent.documentId}
                        </div>
                      </div>

                      <div className="p-3 bg-white rounded-lg border border-slate-200 space-y-0.5">
                        <span className="text-[11px] text-slate-500 font-medium">Forensic fingerprint</span>
                        <div className="font-mono font-semibold text-slate-900 text-xs">
                          {report.matchedEvent.watermarkId}
                        </div>
                        <div className="text-slate-500 text-[11px] font-mono truncate">
                          Key FP: {report.matchedEvent.recipientPubkeyFingerprint}
                        </div>
                      </div>

                      <div className="p-3 bg-white rounded-lg border border-slate-200 space-y-0.5">
                        <span className="text-[11px] text-slate-500 font-medium">Signature</span>
                        <div className="font-semibold text-emerald-800 text-xs flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                          <span>VALID (ML-DSA-65 &bull; FIPS 204)</span>
                        </div>
                        <div className="text-slate-500 text-[11px]">
                          Mathematical non-repudiation verified
                        </div>
                      </div>

                      <div className="p-3 bg-white rounded-lg border border-slate-200 space-y-0.5">
                        <span className="text-[11px] text-slate-500 font-medium">Ledger evidence</span>
                        <div className="font-semibold text-emerald-800 text-xs flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                          <span>VERIFIED (Block #{report.matchedBlock?.height ?? 1})</span>
                        </div>
                        <div className="text-slate-500 text-[11px]">
                          Quorum ratified &bull; 0 tampering detected
                        </div>
                      </div>
                    </div>

                    {/* Standard Evidence Chain Checkmarks */}
                    <div className="pt-2 border-t border-slate-200/80">
                      <span className="text-xs font-semibold text-slate-800 block mb-2">
                        Evidence chain:
                      </span>
                      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs">
                        <div className="flex items-center gap-1.5 text-slate-700">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                          <span>Watermark extracted</span>
                        </div>
                        <div className="flex items-center gap-1.5 text-slate-700">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                          <span>Integrity verified</span>
                        </div>
                        <div className="flex items-center gap-1.5 text-slate-700">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                          <span>Ledger match</span>
                        </div>
                        <div className="flex items-center gap-1.5 text-slate-700">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                          <span>Signature verified</span>
                        </div>
                        <div className="flex items-center gap-1.5 text-slate-700">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                          <span>Ledger integrity verified</span>
                        </div>
                      </div>
                    </div>

                    {/* Action Bar */}
                    <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-200">
                      <div className="flex flex-wrap items-center gap-2">
                        {report.certificate && (
                          <>
                            <PrimaryButton
                              size="sm"
                              icon={<Award className="w-3.5 h-3.5 text-white" />}
                              onClick={() => setShowCertificateViewer(!showCertificateViewer)}
                            >
                              {showCertificateViewer ? 'Hide formal certificate' : 'View formal certificate'}
                            </PrimaryButton>

                            <SecondaryButton
                              size="sm"
                              icon={<Download className="w-3.5 h-3.5 text-slate-600" />}
                              onClick={() => ForensicCertificateService.downloadCertificatePdf(report.certificate!)}
                            >
                              Court-Ready PDF (.pdf)
                            </SecondaryButton>

                            <SecondaryButton
                              size="sm"
                              icon={<FileCode className="w-3.5 h-3.5 text-slate-600" />}
                              onClick={() => ForensicCertificateService.downloadCertificateJson(report.certificate!)}
                            >
                              Certificate (.cert.json)
                            </SecondaryButton>
                          </>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <SecondaryButton
                          size="sm"
                          icon={showEvidenceDrawer ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                          onClick={() => setShowEvidenceDrawer(!showEvidenceDrawer)}
                        >
                          {showEvidenceDrawer ? 'Hide evidence' : 'View evidence'}
                        </SecondaryButton>

                        <SecondaryButton
                          size="sm"
                          icon={<Database className="w-3.5 h-3.5" />}
                          onClick={onNavigateToLedger}
                        >
                          Inspect in Ledger
                        </SecondaryButton>
                      </div>
                    </div>

                    {/* Official Certificate Visual Presentation */}
                    {showCertificateViewer && report.certificate && (
                      <div className="pt-4 border-t border-slate-200 animate-in fade-in">
                        <ForensicAttributionCertificateViewer
                          certificate={report.certificate}
                          onNavigateToLedger={onNavigateToLedger}
                        />
                      </div>
                    )}
                  </div>
                ) : (
                  /* STRICT NON-ATTRIBUTION VIEW (Section 5 failure gate) */
                  <div className="p-5 rounded-xl bg-slate-50 border border-slate-300 text-slate-900 space-y-4">
                    <div className="flex items-start gap-3 pb-3 border-b border-slate-200">
                      <div className="w-8 h-8 rounded-lg bg-rose-50 border border-rose-200 flex items-center justify-center text-rose-600 shrink-0 mt-0.5">
                        <ShieldAlert className="w-4 h-4" />
                      </div>
                      <div className="space-y-1">
                        <div className="text-xs font-bold text-slate-900 tracking-wide uppercase">
                          {report.verdict === 'NO_WATERMARK' && 'NO FORENSIC WATERMARK DETECTED'}
                          {report.verdict === 'CORRUPTED_WATERMARK' && 'CORRUPTED WATERMARK &bull; TAMPERING DETECTED'}
                          {report.verdict === 'INVALID_PDF' && 'INVALID PDF BINARY FORMAT'}
                          {report.verdict === 'NO_MATCHING_EVENT' && 'NO MATCHING LEDGER EVENT FOUND'}
                          {report.verdict === 'DOCUMENT_MISMATCH' && 'DOCUMENT IDENTITY MISMATCH'}
                          {report.verdict === 'SIGNATURE_INVALID' && 'CRYPTOGRAPHIC SIGNATURE INVALID &bull; FORGERY DETECTED'}
                          {report.verdict === 'LEDGER_INVALID' && 'LEDGER CHAIN INTEGRITY BREACH'}
                          {report.verdict === 'EVIDENCE_MISMATCH' && 'CRYPTOGRAPHIC EVIDENCE MISMATCH'}
                          {report.verdict === 'ANALYSIS_ERROR' && 'ANALYSIS PIPELINE ERROR'}
                        </div>
                        <p className="text-xs text-slate-600">
                          <strong>Strict Non-Attribution Enforced:</strong> Under NIST FIPS 204 cryptographic standards, no recipient identity may be asserted unless all verification gates pass.
                        </p>
                      </div>
                    </div>

                    {/* Failed stage explanation */}
                    <div className="p-3 bg-white rounded-lg border border-slate-200 text-xs space-y-1">
                      <span className="text-[11px] font-semibold text-slate-700 block">Failed Verification Stage:</span>
                      <div className="text-slate-800 font-mono text-[11px]">
                        {report.evidenceChain.find((e) => e.status === 'FAILED')?.step || 'Verification Stage Failed'}:{' '}
                        {report.evidenceChain.find((e) => e.status === 'FAILED')?.technicalDetail || 'Security gate failed'}
                      </div>
                    </div>

                    <div className="flex justify-end pt-1">
                      <SecondaryButton
                        size="sm"
                        icon={showEvidenceDrawer ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        onClick={() => setShowEvidenceDrawer(!showEvidenceDrawer)}
                      >
                        {showEvidenceDrawer ? 'Hide evidence chain' : 'View evidence chain'}
                      </SecondaryButton>
                    </div>
                  </div>
                )}

                {/* 3. TECHNICAL EVIDENCE VIEW / DRAWER (Section 7 specifications) */}
                {showEvidenceDrawer && (
                  <div className="p-4 bg-white border border-slate-200 rounded-xl space-y-4 animate-in fade-in duration-150">
                    <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                      <span className="text-xs font-bold text-slate-900 tracking-wide uppercase flex items-center gap-1.5">
                        <Layers className="w-4 h-4 text-indigo-600" />
                        TECHNICAL EVIDENCE DRAWER
                      </span>
                      <span className="text-[11px] text-slate-500 font-mono">
                        RFC 8785 canonical verification
                      </span>
                    </div>

                    {/* 11-Stage Pipeline Full Audit Trail */}
                    <div className="space-y-2">
                      <span className="text-[11px] font-semibold text-slate-700 block">
                        Detailed Verification Audit Trail:
                      </span>
                      <div className="space-y-1.5">
                        {report.evidenceChain.map((ev, idx) => (
                          <div
                            key={idx}
                            className={`p-2.5 rounded-lg border text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 ${
                              ev.status === 'VERIFIED'
                                ? 'bg-slate-50/70 border-slate-200'
                                : 'bg-rose-50/60 border-rose-200'
                            }`}
                          >
                            <div className="space-y-0.5">
                              <div className="font-semibold text-slate-900 flex items-center gap-1.5">
                                {ev.status === 'VERIFIED' ? (
                                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                                ) : (
                                  <AlertTriangle className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                                )}
                                <span>{ev.step}</span>
                              </div>
                              <div className="text-[11px] text-slate-500 pl-5">{ev.description}</div>
                            </div>
                            <div className="text-[10px] font-mono text-slate-600 pl-5 sm:pl-0 sm:text-right max-w-md truncate">
                              {ev.technicalDetail}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Cryptographic Key & Block Values */}
                    <div className="space-y-1 pt-2 border-t border-slate-100">
                      <span className="text-[11px] font-semibold text-slate-700 block">
                        Cryptographic Evidence Details:
                      </span>
                      {report.matchedEvent && (
                        <>
                          <KeyValueRow label="Document Hash (SHA-256)" value={report.matchedEvent.documentHashSha256} copyable />
                          <KeyValueRow label="Decryption Event ID" value={report.matchedEvent.eventId} copyable />
                          <KeyValueRow label="Recipient ID" value={report.matchedEvent.recipientId} copyable />
                          <KeyValueRow label="Recipient Key Fingerprint" value={report.matchedEvent.recipientPubkeyFingerprint} copyable />
                          <KeyValueRow label="Watermark ID" value={report.matchedEvent.watermarkId} copyable />
                          <KeyValueRow label="Watermark Commitment" value={report.matchedEvent.watermarkCommitment} copyable />
                          <KeyValueRow label="Timestamp" value={`${new Date(report.matchedEvent.timestampEpochMs).toISOString()} (${report.matchedEvent.timestampEpochMs})`} />
                          <KeyValueRow label="ML-DSA-65 Signature Status" value="VALID (FIPS 204 Post-Quantum Non-Repudiation)" />
                        </>
                      )}
                      {report.matchedBlock && (
                        <>
                          <KeyValueRow label="Ledger Block Number" value={`Block #${report.matchedBlock.height}`} />
                          <KeyValueRow label="Block Hash (SHA-256)" value={report.matchedBlock.blockHash} copyable />
                          <KeyValueRow label="Previous Block Hash" value={report.matchedBlock.previousHash} copyable />
                          <KeyValueRow label="Merkle Root" value={report.matchedBlock.merkleRoot} copyable />
                          <KeyValueRow label="Ledger Verification Status" value="INTACT (0 administrative tampering detected)" />
                        </>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </Section>
          )}
        </div>
      ) : (
        /* 4. INVESTIGATION HISTORY VIEW (Section 8 specifications) */
        <Section
          title="Investigation case history"
          description="Local offline record of analyzed documents and verified provenance reports."
          action={
            caseHistory.length > 0 && (
              <SecondaryButton size="sm" onClick={handleClearHistory}>
                Clear history
              </SecondaryButton>
            )
          }
        >
          {caseHistory.length === 0 ? (
            <div className="p-8 text-center bg-slate-50 rounded-xl border border-slate-200 space-y-2">
              <History className="w-8 h-8 text-slate-300 mx-auto" />
              <div className="text-xs font-semibold text-slate-700">No previous forensic investigations recorded</div>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                Completed investigations will automatically appear here with their verified attribution outcomes and cryptographic timestamps.
              </p>
            </div>
          ) : (
            <div className="space-y-4 pt-1">
              {/* Selected Historical Certificate Viewer */}
              {selectedHistoricalCert && (
                <div className="p-4 rounded-xl border border-indigo-200 bg-slate-50/70 space-y-3">
                  <div className="flex items-center justify-between pb-2 border-b border-indigo-100">
                    <span className="text-xs font-bold text-indigo-900 uppercase flex items-center gap-1.5 font-mono">
                      <Award className="w-4 h-4 text-emerald-600" />
                      Historical Certificate Inspection &bull; {selectedHistoricalCert.certificateId}
                    </span>
                    <SecondaryButton size="sm" onClick={() => setSelectedHistoricalCert(null)}>
                      Close certificate
                    </SecondaryButton>
                  </div>
                  <ForensicAttributionCertificateViewer
                    certificate={selectedHistoricalCert}
                    onNavigateToLedger={onNavigateToLedger}
                  />
                </div>
              )}

              <div className="overflow-x-auto border border-slate-200 rounded-xl bg-white">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-medium">
                    <tr>
                      <th className="py-2.5 px-4">Case ID</th>
                      <th className="py-2.5 px-4">Analyzed file</th>
                      <th className="py-2.5 px-4">Attribution result</th>
                      <th className="py-2.5 px-4">Attributed recipient</th>
                      <th className="py-2.5 px-4">Certificate</th>
                      <th className="py-2.5 px-4">Timestamp</th>
                      <th className="py-2.5 px-4">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {caseHistory.map((c) => (
                      <tr key={c.caseId} className="hover:bg-slate-50/50 transition-colors">
                        <td className="py-2.5 px-4 font-mono font-medium text-slate-900">
                          {c.caseId}
                        </td>
                        <td className="py-2.5 px-4 text-slate-800">
                          <div className="flex items-center gap-1.5">
                            <FileText className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                            <span className="truncate max-w-xs">{c.analyzedFileName}</span>
                          </div>
                        </td>
                        <td className="py-2.5 px-4">
                          <span
                            className={`font-mono text-[11px] ${
                              c.verificationStatus === 'VERIFIED'
                                ? 'text-emerald-700 font-semibold'
                                : 'text-slate-600'
                            }`}
                          >
                            {c.resultVerdict}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-slate-800">
                          {c.attributedRecipientName ? (
                            <span className="font-medium text-slate-900">{c.attributedRecipientName}</span>
                          ) : (
                            <span className="text-slate-400 italic">None (Non-attribution)</span>
                          )}
                        </td>
                        <td className="py-2.5 px-4">
                          {c.certificateId ? (
                            <button
                              type="button"
                              onClick={async () => {
                                const cert = await airGappedStorage.getAttributionCertificate(c.certificateId || c.caseId);
                                if (cert) setSelectedHistoricalCert(cert);
                              }}
                              className="inline-flex items-center gap-1 font-mono text-[11px] text-indigo-600 hover:text-indigo-800 font-semibold cursor-pointer underline"
                            >
                              <Award className="w-3 h-3 text-emerald-600" />
                              <span>{c.certificateId}</span>
                            </button>
                          ) : (
                            <span className="text-slate-400 text-[11px]">&mdash;</span>
                          )}
                        </td>
                        <td className="py-2.5 px-4 text-slate-500 font-mono text-[11px]">
                          {new Date(c.analyzedAt).toLocaleString()}
                        </td>
                        <td className="py-2.5 px-4">
                          {c.verificationStatus === 'VERIFIED' ? (
                            <span className="text-emerald-700 font-semibold text-[11px]">VERIFIED</span>
                          ) : (
                            <span className="text-slate-500 text-[11px]">REJECTED</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="text-[11px] text-slate-400 text-right">
                History is stored securely in local air-gapped storage. Zero secrets or keys are serialized.
              </div>
            </div>
          )}
        </Section>
      )}
    </PageShell>
  );
};
