import React, { useState, useEffect } from 'react';
import {
  FileText,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Download,
  CheckCircle2,
  XCircle,
  Clock,
  User,
  Key,
  Package,
  Database,
  ExternalLink,
  Copy,
  Check,
  RefreshCw,
} from 'lucide-react';
import {
  ForensicDossier,
  DossierVerificationResult,
} from '../types/dossier';
import { SecurityIncident } from '../types/incident';
import { ForensicDossierService } from '../services/forensicDossierService';
import { PrimaryButton, SecondaryButton, KeyValueRow } from './ui/designSystem';

interface ForensicDossierModalProps {
  incident: SecurityIncident;
  onClose: () => void;
  onDossierGenerated?: () => void;
}

export const ForensicDossierModal: React.FC<ForensicDossierModalProps> = ({
  incident,
  onClose,
  onDossierGenerated,
}) => {
  const [dossier, setDossier] = useState<ForensicDossier | null>(null);
  const [verification, setVerification] = useState<DossierVerificationResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [copiedDigest, setCopiedDigest] = useState<boolean>(false);

  useEffect(() => {
    generateInitialDossier();
  }, [incident.incidentId]);

  const generateInitialDossier = async () => {
    setIsLoading(true);
    try {
      const generated = await ForensicDossierService.generateDossier(incident, {
        id: 'SOC-INVESTIGATOR-01',
        name: 'Lead Forensic Investigator',
        role: 'Chief Security Officer',
      });
      setDossier(generated);
      const verified = await ForensicDossierService.verifyDossier(generated);
      setVerification(verified);
      onDossierGenerated?.();
    } catch (e) {
      console.error('[DossierModal] Failed to compile dossier:', e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleReverify = async () => {
    if (!dossier) return;
    setIsVerifying(true);
    try {
      const verified = await ForensicDossierService.verifyDossier(dossier);
      setVerification(verified);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleDownloadJson = () => {
    if (!dossier) return;
    const jsonStr = JSON.stringify(dossier, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${dossier.dossierId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadPdf = async () => {
    if (!dossier) return;
    try {
      const pdfBytes = await ForensicDossierService.generateDossierPdf(dossier);
      const blob = new Blob([pdfBytes as unknown as BlobPart], { type: 'application/pdf' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${dossier.dossierId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error('[DossierModal] Failed to generate PDF:', e);
    }
  };

  const copyDigest = () => {
    if (!dossier) return;
    navigator.clipboard.writeText(dossier.dossierDigestSha256);
    setCopiedDigest(true);
    setTimeout(() => setCopiedDigest(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-2xs flex items-center justify-center p-4 animate-in fade-in">
      <div className="bg-white rounded-2xl shadow-2xl max-w-3xl w-full max-h-[90vh] flex flex-col overflow-hidden border border-slate-200">
        {/* Header */}
        <div className="p-5 border-b border-slate-200 flex items-start justify-between bg-slate-50">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-indigo-600">
                {dossier ? dossier.dossierId : 'Generating Dossier...'}
              </span>
              {verification?.valid ? (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
                  CRYPTOGRAPHICALLY VERIFIED
                </span>
              ) : !verification?.digestMatch ? (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300">
                  DOSSIER CONTENT TAMPERED
                </span>
              ) : !verification?.currentLiveVerification.auditChainValid ? (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300">
                  AUDIT HASH CHAIN COMPROMISED
                </span>
              ) : !verification?.currentLiveVerification.allEvidenceEventsMatchLiveStore ? (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300">
                  EVIDENCE REFERENCE MISMATCH
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-100 text-amber-800 border border-amber-300">
                  VERIFICATION FAILED / UNVERIFIED
                </span>
              )}
            </div>
            <h3 className="text-base font-bold text-slate-900">
              Official Forensic Investigation Dossier
            </h3>
            <div className="text-[11px] font-mono text-slate-500">
              Linked Incident: {incident.incidentId} &bull; Compiled: {dossier ? new Date(dossier.generatedAtEpochMs).toLocaleString() : '...'}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-700 cursor-pointer font-bold text-sm"
          >
            ✕
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isLoading ? (
            <div className="p-12 text-center space-y-3">
              <RefreshCw className="w-8 h-8 text-indigo-600 animate-spin mx-auto" />
              <div className="text-xs font-semibold text-slate-700">Compiling and cross-verifying dossier evidence...</div>
            </div>
          ) : !dossier ? (
            <div className="p-8 text-center text-xs text-rose-600">Failed to compile forensic dossier.</div>
          ) : (
            <>
              {/* Executive Assessment Box */}
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2 text-xs">
                <span className="font-bold text-slate-800 uppercase tracking-wider block">
                  I. Incident Executive Assessment
                </span>
                <KeyValueRow label="Detection Rule" value={`${dossier.incidentSummary.detectionRuleName} (${dossier.incidentSummary.ruleId})`} />
                <KeyValueRow label="Incident Type" value={dossier.incidentSummary.incidentType} />
                <KeyValueRow label="Severity & Confidence" value={`${dossier.incidentSummary.severity} (Confidence: ${dossier.incidentSummary.confidence})`} />
                <KeyValueRow label="Status" value={dossier.incidentSummary.status} />
                <p className="pt-2 text-slate-700 font-mono text-[11px] bg-white p-2.5 rounded border border-slate-200">
                  {dossier.incidentSummary.description}
                </p>
              </div>

              {/* Cryptographic Verification Status (Separate Issuance vs Live) */}
              <div className="p-4 bg-slate-900 text-white rounded-xl space-y-3 text-xs font-mono">
                <div className="flex items-center justify-between pb-2 border-b border-slate-700">
                  <span className="font-bold text-slate-300">CRYPTOGRAPHIC INTEGRITY CHECKS</span>
                  <button
                    type="button"
                    onClick={handleReverify}
                    disabled={isVerifying}
                    className="text-[10px] text-indigo-300 hover:text-indigo-100 underline cursor-pointer"
                  >
                    {isVerifying ? 'Verifying...' : 'Re-verify Live Store'}
                  </button>
                </div>

                {/* Issuance Snapshot vs Current Live State */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
                  <div className="space-y-1 p-2.5 bg-slate-800 rounded">
                    <span className="text-slate-400 block font-bold">AT ISSUANCE:</span>
                    <div>Audit Chain: {dossier.issuanceVerification.auditChainValid ? '✓ INTACT' : '✖ TAMPERED'}</div>
                    <div className="text-slate-400">Head: {dossier.issuanceVerification.auditChainHeadDigest.slice(0, 16)}...</div>
                    <div className="text-slate-400">Events Checked: {dossier.issuanceVerification.auditChainEventsChecked}</div>
                  </div>

                  <div className="space-y-1 p-2.5 bg-slate-800 rounded">
                    <span className="text-slate-400 block font-bold">CURRENT LIVE AUDIT:</span>
                    <div className={verification?.currentLiveVerification.auditChainValid ? 'text-emerald-400' : 'text-rose-400'}>
                      Audit Chain: {verification?.currentLiveVerification.auditChainValid ? '✓ INTACT' : '✖ TAMPERED'}
                    </div>
                    <div className="text-slate-400">Head: {verification?.currentLiveVerification.auditChainHeadDigest.slice(0, 16)}...</div>
                    <div className="text-slate-400">Evidence Match: {verification?.currentLiveVerification.allEvidenceEventsMatchLiveStore ? '✓ 100%' : '✖ Mismatch'}</div>
                  </div>
                </div>

                {/* Canonical SHA-256 Digest */}
                <div className="space-y-1 pt-1">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-[10px]">Canonical Content Digest (SHA-256):</span>
                    <button
                      type="button"
                      onClick={copyDigest}
                      className="text-[10px] text-indigo-300 hover:text-indigo-100 flex items-center gap-1 cursor-pointer"
                    >
                      {copiedDigest ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="text-[10px] text-emerald-300 break-all bg-black/40 p-2 rounded">
                    {dossier.dossierDigestSha256}
                  </div>
                </div>

                {/* Structured Verification Checks */}
                {verification?.checks && (
                  <div className="space-y-1 pt-1 border-t border-slate-700">
                    {verification.checks.map((chk, idx) => (
                      <div key={idx} className="flex items-start gap-2 text-[10px]">
                        {chk.passed ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                        )}
                        <div>
                          <span className="font-bold text-slate-300">{chk.check}:</span> {chk.message}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Evidence Timeline */}
              <div className="space-y-2">
                <span className="text-xs font-bold text-slate-800 uppercase tracking-wider block">
                  II. Cryptographic Evidence Chain ({dossier.evidenceTimeline.length} Records)
                </span>
                <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                  {dossier.evidenceTimeline.map((evt) => (
                    <div key={evt.eventId} className="p-2.5 bg-white border border-slate-200 rounded-lg text-xs flex items-center justify-between">
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-slate-900">{evt.eventType}</span>
                          <span className="text-[10px] font-mono text-slate-400">{evt.eventId}</span>
                        </div>
                        <p className="text-slate-600 text-[11px] truncate">{evt.summary}</p>
                      </div>
                      <div className="text-right text-[10px] font-mono">
                        <span className={evt.outcome === 'SUCCESS' ? 'text-emerald-700 font-bold' : 'text-rose-600 font-bold'}>
                          {evt.outcome}
                        </span>
                        <div className="text-slate-400">{new Date(evt.timestampEpochMs).toLocaleTimeString()}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Mandatory Disclaimers */}
              <div className="p-3 bg-amber-50/70 border border-amber-200 rounded-xl space-y-1.5 text-[11px] text-amber-900">
                <div className="font-bold flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-600" />
                  <span>MANDATORY LEGAL BOUNDARY & INTENT DISCLAIMER</span>
                </div>
                <p>{dossier.limitations.intentDisclaimer}</p>
                <p className="text-slate-500 font-mono text-[10px]">{dossier.limitations.simulatedInfrastructureNotice}</p>
              </div>
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <span className="text-[11px] font-mono text-slate-500">
            Export formats: Human-readable PDF &bull; Machine-readable RFC 8785 JSON
          </span>
          <div className="flex items-center gap-2">
            <SecondaryButton size="sm" icon={<Download className="w-3.5 h-3.5" />} onClick={handleDownloadJson} disabled={isLoading || !dossier}>
              Download JSON
            </SecondaryButton>
            <PrimaryButton size="sm" icon={<Download className="w-3.5 h-3.5" />} onClick={handleDownloadPdf} disabled={isLoading || !dossier}>
              Download PDF Dossier
            </PrimaryButton>
          </div>
        </div>
      </div>
    </div>
  );
};
