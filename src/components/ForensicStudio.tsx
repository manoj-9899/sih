import React, { useState, useEffect } from 'react';
import {
  Search,
  ShieldCheck,
  AlertTriangle,
  FileSearch,
  CheckCircle2,
  XCircle,
  FileText,
  Key,
  Database,
  ArrowRight,
  Download,
  Copy,
  Check,
  Terminal,
  Fingerprint,
  Radio,
  FileSignature,
  Layers,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { ForensicAttributionReport, UiMode } from '../types';
import { DistributionService } from '../services/distributionService';
import { GuidancePanel } from './ui/GuidancePanel';
import {
  WorkstationSurface,
  OperationalButton,
  StatusBadge,
  CryptoDataBlock,
  TechnicalMetricTile,
} from './ui/WorkstationPrimitives';
import { ForensicAttributionCertificateViewer } from './ForensicAttributionCertificateViewer';
import { CertificateVerificationSection } from './CertificateVerificationSection';

interface ForensicStudioProps {
  initialLeakedText?: string;
  leakedMetadata?: { title: string; recipientName: string } | null;
  onNavigateToLedger: () => void;
  uiMode?: UiMode;
}

export const ForensicStudio: React.FC<ForensicStudioProps> = ({
  initialLeakedText,
  leakedMetadata,
  onNavigateToLedger,
  uiMode = 'workstation',
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'investigate' | 'verify_certificate'>('investigate');
  const [leakedContent, setLeakedContent] = useState<string>(initialLeakedText || '');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [report, setReport] = useState<ForensicAttributionReport | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showRawSignature, setShowRawSignature] = useState<boolean>(false);

  useEffect(() => {
    if (initialLeakedText) {
      setLeakedContent(initialLeakedText);
      setReport(null);
    }
  }, [initialLeakedText]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleRunInvestigation = async () => {
    if (!leakedContent.trim()) return;
    setIsAnalyzing(true);
    setReport(null);

    try {
      await new Promise((r) => setTimeout(r, 550));
      const generatedReport = await DistributionService.investigateLeakedDocument(leakedContent);
      setReport(generatedReport);
    } catch (err) {
      console.error('Forensic analysis failed:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      {uiMode === 'guided' && (
        <GuidancePanel
          stepNumber="3"
          title="Blind Forensic Steganography Extraction & Ledger Attribution"
          summary="An investigator pastes or uploads an unattributed leaked document. The forensic engine blindly scans zero-width character sequences, recovers the hidden 32-byte session payload, matches it against the immutable DLT, and verifies the recipient's ML-DSA-65 digital signature."
          recommendedAction="Ensure the leaked document text is in the box below and click 'EXECUTE BLIND FORENSIC ATTRIBUTION'."
          whatToObserve="Observe the 100% confidence verdict and download the court-ready Forensic Certificate (.json) linking the leak directly to the perpetrator."
          actionButtonLabel="Execute Attribution"
          onActionClick={handleRunInvestigation}
        />
      )}

      {/* 1. OPERATIONAL CONTEXT HEADER */}
      <WorkstationSurface variant="primary" className="p-4 sm:p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status="inspection" icon={<Fingerprint className="w-3.5 h-3.5 text-sky-600" />}>
              FORENSIC LAB
            </StatusBadge>
            <span className="text-[11px] font-mono text-slate-600 px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200">
              BLIND STEGANOGRAPHY
            </span>
            <span className="text-[11px] font-mono text-slate-600 px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200">
              ML-DSA-65 (FIPS 204)
            </span>
            <span className="text-[11px] font-mono text-emerald-700 px-2 py-0.5 rounded-md bg-emerald-50 border border-emerald-200">
              LEDGER VERIFIED
            </span>
          </div>

          <div className="shrink-0 flex items-center gap-2">
            <div className="inline-flex p-0.5 rounded-lg bg-slate-100 border border-slate-200 text-xs font-mono">
              <button
                type="button"
                onClick={() => setActiveSubTab('investigate')}
                className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${
                  activeSubTab === 'investigate'
                    ? 'bg-white text-slate-900 font-bold shadow-xs'
                    : 'text-slate-500 hover:text-slate-900'
                }`}
              >
                1. Investigate Document
              </button>
              <button
                type="button"
                onClick={() => setActiveSubTab('verify_certificate')}
                className={`px-3 py-1 rounded-md transition-colors cursor-pointer flex items-center gap-1.5 ${
                  activeSubTab === 'verify_certificate'
                    ? 'bg-white text-slate-900 font-bold shadow-xs'
                    : 'text-slate-500 hover:text-slate-900'
                }`}
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                2. Audit Certificate (.json)
              </button>
            </div>

            {activeSubTab === 'investigate' && (
              <OperationalButton
                variant="operational"
                size="sm"
                onClick={handleRunInvestigation}
                disabled={isAnalyzing || !leakedContent.trim()}
                icon={<Search className="w-3.5 h-3.5" />}
              >
                {isAnalyzing ? 'EXTRACTING...' : 'EXECUTE BLIND ATTRIBUTION'}
              </OperationalButton>
            )}
          </div>
        </div>
      </WorkstationSurface>

      {activeSubTab === 'verify_certificate' ? (
        <CertificateVerificationSection onNavigateToLedger={onNavigateToLedger} />
      ) : (
        /* 2. MAIN INVESTIGATION WORKBENCH */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Leaked Artifact Ingestion */}
        <div className="lg:col-span-5 space-y-6">
          <WorkstationSurface variant="primary" className="space-y-4">
            <div className="flex items-center justify-between pb-2.5 border-b border-slate-200 text-xs font-mono">
              <span className="font-semibold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <FileSearch className="w-4 h-4 text-slate-600" />
                Leaked Artifact Ingestion
              </span>
              {leakedMetadata && (
                <span className="text-[10px] px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-bold">
                  SIMULATED TARGET
                </span>
              )}
            </div>

            <div>
              <div className="flex justify-between items-center mb-1.5 text-xs font-mono">
                <span className="text-slate-500 font-medium">DOCUMENT CARRIER TEXT</span>
                <label className="cursor-pointer text-xs text-indigo-600 hover:text-indigo-800 flex items-center gap-1 font-medium transition-colors">
                  <Download className="w-3.5 h-3.5 rotate-180 text-indigo-600" />
                  <span>Upload .txt/.md</span>
                  <input
                    type="file"
                    accept=".txt,.md"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      const reader = new FileReader();
                      reader.onload = (event) => {
                        const content = event.target?.result as string;
                        if (content) {
                          setLeakedContent(content);
                          setReport(null);
                        }
                      };
                      reader.readAsText(file);
                    }}
                  />
                </label>
              </div>

              <textarea
                value={leakedContent}
                onChange={(e) => setLeakedContent(e.target.value)}
                placeholder="Paste leaked text here or trigger 'Simulate Leak' from the Recipient Portal..."
                rows={11}
                className="w-full p-3.5 rounded-lg bg-slate-50 border border-slate-300 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none resize-none leading-relaxed"
              />
            </div>

            <div className="pt-1">
              <OperationalButton
                variant="operational"
                size="lg"
                onClick={handleRunInvestigation}
                disabled={isAnalyzing || !leakedContent.trim()}
                className="w-full"
                icon={<Search className="w-4 h-4" />}
                data-tour-target="execute-attribution-btn"
              >
                {isAnalyzing
                  ? 'EXTRACTING STEGANOGRAPHY & QUERYING DLT...'
                  : 'EXECUTE BLIND FORENSIC ATTRIBUTION'}
              </OperationalButton>
            </div>
          </WorkstationSurface>

          <WorkstationSurface variant="elevated" className="space-y-2.5 text-xs font-mono">
            <span className="text-xs text-slate-900 uppercase font-bold tracking-wider block">
              Forensic Extraction Parameters
            </span>
            <div className="space-y-1.5 text-xs text-slate-700">
              <div className="flex justify-between p-2 rounded bg-slate-50 border border-slate-200">
                <span className="text-slate-500">Carrier Method:</span>
                <span className="font-semibold text-slate-800">Zero-Width Whitespace</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-slate-50 border border-slate-200">
                <span className="text-slate-500">Bit Invariance:</span>
                <span className="font-semibold text-slate-800">SSIM &gt; 0.999 &bull; PSNR &gt; 49 dB</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-slate-50 border border-slate-200">
                <span className="text-slate-500">False Positive Rate:</span>
                <span className="font-semibold text-emerald-700">Zero Mathematical Ambiguity</span>
              </div>
            </div>
          </WorkstationSurface>
        </div>

        {/* Right Column: Formal Certificate & Evidence Chain */}
        <div className="lg:col-span-7 space-y-6">
          {report ? (
            report.certificate ? (
              <ForensicAttributionCertificateViewer
                certificate={report.certificate}
                onNavigateToLedger={onNavigateToLedger}
              />
            ) : (
              <WorkstationSurface variant="primary" className="p-6 space-y-4">
                <div className="flex items-start gap-3 pb-3 border-b border-amber-200">
                  <div className="w-8 h-8 rounded-lg bg-amber-50 border border-amber-200 flex items-center justify-center text-amber-600 shrink-0">
                    <AlertTriangle className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-slate-900 uppercase">
                      STRICT NON-ATTRIBUTION ENFORCED ({report.attributionVerdict})
                    </h4>
                    <p className="text-xs text-slate-600 font-sans mt-0.5">
                      Under NIST FIPS 204 cryptographic standards, no recipient attribution certificate may be issued unless all verification gates pass.
                    </p>
                  </div>
                </div>

                <div className="space-y-2 font-mono text-xs">
                  {report.evidenceChain.map((ev, idx) => (
                    <div
                      key={idx}
                      className={`p-2.5 rounded-lg border flex items-center justify-between ${
                        ev.status === 'VERIFIED'
                          ? 'bg-slate-50 border-slate-200'
                          : 'bg-rose-50 border-rose-200 text-rose-900'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        {ev.status === 'VERIFIED' ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                        )}
                        <span className="font-semibold">{ev.step}</span>
                      </div>
                      <span className="text-[10px] text-slate-500 truncate max-w-xs">{ev.technicalDetail}</span>
                    </div>
                  ))}
                </div>
              </WorkstationSurface>
            )
          ) : (
            <WorkstationSurface variant="primary" className="h-full flex flex-col items-center justify-center p-12 text-center text-slate-500 border border-dashed border-slate-300 rounded-xl font-mono min-h-[380px]">
              <Search className="w-10 h-10 mb-3 opacity-40 text-slate-400" />
              <h4 className="text-sm font-bold text-slate-800">Awaiting Leaked Document Ingestion</h4>
              <p className="text-xs text-slate-500 mt-1.5 max-w-sm font-sans">
                Paste an unattributed document or trigger a simulated leak from the Recipient Portal, then click &apos;Execute Blind Attribution&apos;.
              </p>
            </WorkstationSurface>
          )}
        </div>
      </div>
      )}
    </div>
  );
};
