import React, { useState } from 'react';
import {
  FileText,
  Upload,
  Lock,
  CheckCircle2,
  Users,
  Layers,
  ArrowRight,
  Shield,
  FileCode,
  Copy,
  Check,
  Plus,
  X,
  FileUp,
  AlertTriangle,
  Download,
} from 'lucide-react';
import {
  PageShell,
  PageHeader,
  Section,
  PrimaryButton,
  SecondaryButton,
  StatusBadge,
  KeyValueRow,
  HashDisplay,
  TechnicalDetails,
  EmptyState,
} from './ui/designSystem';
import { ClassifiedDocument, Recipient, EncryptedPackage } from '../types';
import { DistributionService } from '../services/distributionService';
import { PackageExportService } from '../services/packageExportService';
import { validatePdfBytes } from '../crypto/pdfUtils';

interface DocumentsViewProps {
  documents: ClassifiedDocument[];
  recipients: Recipient[];
  activePackage: EncryptedPackage | null;
  onPackageCreated: (pkg: EncryptedPackage) => void;
  onNavigateToDecrypt: () => void;
  onAddDocument?: (doc: ClassifiedDocument) => void;
}

export const DocumentsView: React.FC<DocumentsViewProps> = ({
  documents,
  recipients,
  activePackage,
  onPackageCreated,
  onNavigateToDecrypt,
  onAddDocument,
}) => {
  const [selectedDocId, setSelectedDocId] = useState<string>(documents[0]?.id || '');
  const [selectedRecipientIds, setSelectedRecipientIds] = useState<string[]>(
    recipients.slice(0, 2).map((r) => r.id) // Default Alice & Bob
  );
  const [isPackaging, setIsPackaging] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);

  // New Document Upload State
  const [newTitle, setNewTitle] = useState('');
  const [newClassification, setNewClassification] = useState<'TOP SECRET // SCI' | 'SECRET' | 'CONFIDENTIAL'>('CONFIDENTIAL');
  const [newSummary, setNewSummary] = useState('');
  const [newText, setNewText] = useState('');
  const [uploadedPdfBytes, setUploadedPdfBytes] = useState<Uint8Array | null>(null);
  const [pdfFileName, setPdfFileName] = useState<string>('');
  const [pdfFileSize, setPdfFileSize] = useState<number>(0);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [isPdfUpload, setIsPdfUpload] = useState<boolean>(true);
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [exportMessage, setExportMessage] = useState<string | null>(null);

  const selectedDoc = documents.find((d) => d.id === selectedDocId) || documents[0];

  const handleToggleRecipient = (id: string) => {
    setSelectedRecipientIds((prev) =>
      prev.includes(id) ? prev.filter((rId) => rId !== id) : [...prev, id]
    );
  };

  const handleExportSihpkg = async () => {
    if (!activePackage) return;
    setIsExporting(true);
    setExportMessage('Preparing secure package...');
    try {
      await new Promise((r) => setTimeout(r, 200));
      const binary = await PackageExportService.exportPackageToBinary(activePackage);
      const filename = `${activePackage.filename ? activePackage.filename.replace(/\.[^/.]+$/, '') : activePackage.documentTitle.replace(/\s+/g, '_')}.sihpkg`;
      PackageExportService.triggerDownload(binary, filename);
      setExportMessage(`Package created successfully: ${filename}`);
      setTimeout(() => setExportMessage(null), 4000);
    } catch (err: any) {
      setExportMessage(`Export error: ${err.message}`);
    } finally {
      setIsExporting(false);
    }
  };

  const handleCreatePackage = async () => {
    if (!selectedDoc || selectedRecipientIds.length === 0) return;
    setIsPackaging(true);
    try {
      const authorizedRecips = recipients.filter((r) => selectedRecipientIds.includes(r.id));
      const pkg = await DistributionService.createEncryptedPackage(selectedDoc, authorizedRecips);
      onPackageCreated(pkg);
    } catch (err) {
      console.error('Packaging error:', err);
    } finally {
      setIsPackaging(false);
    }
  };

  const handlePdfFileSelection = async (file: File) => {
    setUploadError(null);
    if (!file) return;

    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      const validation = validatePdfBytes(bytes);

      if (!validation.isValid) {
        setUploadError(`Invalid PDF File: ${validation.error || 'The uploaded file does not contain a valid %PDF- header.'}`);
        setUploadedPdfBytes(null);
        return;
      }

      setUploadedPdfBytes(bytes);
      setPdfFileName(file.name);
      setPdfFileSize(file.size);
      if (!newTitle) {
        setNewTitle(file.name.replace(/\.pdf$/i, '').replace(/[-_]/g, ' '));
      }
      if (!newSummary) {
        setNewSummary(`Classified PDF document (${(file.size / 1024).toFixed(1)} KB, PDF v${validation.version || '1.4'}).`);
      }
    } catch (err: any) {
      setUploadError(`File read error: ${err.message || 'Could not parse selected file.'}`);
      setUploadedPdfBytes(null);
    }
  };

  const handleUploadSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim() || !onAddDocument) return;

    if (isPdfUpload && !uploadedPdfBytes) {
      setUploadError('Please select a valid PDF file to upload.');
      return;
    }

    if (!isPdfUpload && !newText.trim()) {
      setUploadError('Please enter document content.');
      return;
    }

    const newDoc: ClassifiedDocument = {
      id: `DOC-${Date.now().toString(36).toUpperCase()}`,
      title: newTitle,
      classification: newClassification,
      caveats: 'RESTRICTED DISSEMINATION',
      originatingOffice: 'Directorate of Strategic Operations',
      summary: newSummary || (isPdfUpload ? 'Uploaded PDF binary report.' : 'Uploaded confidential report.'),
      rawText: isPdfUpload
        ? `[BINARY PDF DOCUMENT: ${pdfFileName || newTitle}]\nFile size: ${pdfFileSize} bytes\nFormat: application/pdf\nStatus: Ingested as raw binary stream`
        : newText,
      visualPages: [],
      createdAt: Date.now(),
      isPdf: isPdfUpload,
      mimeType: isPdfUpload ? 'application/pdf' : 'text/plain',
      filename: isPdfUpload ? (pdfFileName || `${newTitle.replace(/\s+/g, '_')}.pdf`) : `${newTitle.replace(/\s+/g, '_')}.txt`,
      fileSizeBytes: isPdfUpload ? pdfFileSize : new TextEncoder().encode(newText).length,
      pdfBytes: isPdfUpload && uploadedPdfBytes ? uploadedPdfBytes : undefined,
    };

    onAddDocument(newDoc);
    setSelectedDocId(newDoc.id);
    setShowUploadModal(false);
    setNewTitle('');
    setNewSummary('');
    setNewText('');
    setUploadedPdfBytes(null);
    setPdfFileName('');
    setPdfFileSize(0);
    setUploadError(null);
  };

  return (
    <PageShell>
      <PageHeader
        title="Documents"
        description="Manage protected documents and prepare secure distribution."
        action={
          <PrimaryButton
            size="sm"
            icon={<Upload className="w-3.5 h-3.5" />}
            onClick={() => setShowUploadModal(true)}
          >
            Upload document
          </PrimaryButton>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Document List */}
        <div className="lg:col-span-5 space-y-4">
          <Section title="Protected documents" description={`${documents.length} documents registered in local repository.`}>
            <div className="space-y-2 mt-2">
              {documents.map((doc) => {
                const isSelected = doc.id === selectedDocId;
                const isTopSecret = doc.classification.includes('TOP SECRET');

                return (
                  <div
                    key={doc.id}
                    onClick={() => setSelectedDocId(doc.id)}
                    className={`p-3.5 rounded-lg border transition-all cursor-pointer select-none ${
                      isSelected
                        ? 'border-indigo-500 bg-indigo-50/40 text-slate-900 shadow-2xs ring-1 ring-indigo-200'
                        : 'border-slate-200/80 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50/60'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[11px] mb-1">
                      <span
                        className={`px-1.5 py-0.5 rounded font-mono font-medium ${
                          isTopSecret
                            ? 'bg-rose-50 text-rose-700 border border-rose-200'
                            : 'bg-slate-100 text-slate-600 border border-slate-200'
                        }`}
                      >
                        {doc.classification}
                      </span>
                      <span className="text-slate-400 font-mono text-[10px]">
                        PDF &bull; ~24 KB
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-slate-900 line-clamp-1">
                      {doc.title}
                    </h4>
                    <p className="text-[11px] text-slate-500 line-clamp-2 mt-1 leading-normal">
                      {doc.summary}
                    </p>
                  </div>
                );
              })}
            </div>
          </Section>
        </div>

        {/* Right: Distribution Configuration & Packaging */}
        <div className="lg:col-span-7 space-y-6">
          {selectedDoc ? (
            <Section
              title="Distribution preparation"
              description="Select authorized recipients. Each recipient receives a unique post-quantum keywrap."
              action={
                <span className="text-[11px] font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                  ML-KEM-768 &bull; AES-256-GCM
                </span>
              }
            >
              <div className="space-y-4 pt-1">
                {/* Document summary box */}
                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200/80 space-y-1 text-xs">
                  <div className="font-semibold text-slate-900">{selectedDoc.title}</div>
                  <div className="text-[11px] text-slate-500">
                    Document ID: <span className="font-mono">{selectedDoc.id}</span>
                  </div>
                </div>

                {/* Recipient authorization list */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-slate-900 block">
                    Authorize recipients ({selectedRecipientIds.length} of {recipients.length} selected):
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {recipients.map((recip) => {
                      const isChecked = selectedRecipientIds.includes(recip.id);
                      return (
                        <div
                          key={recip.id}
                          onClick={() => handleToggleRecipient(recip.id)}
                          className={`p-2.5 rounded-lg border transition-all cursor-pointer flex items-center justify-between gap-2 select-none ${
                            isChecked
                              ? 'border-indigo-400 bg-indigo-50/30 shadow-2xs'
                              : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50'
                          }`}
                        >
                          <div className="min-w-0">
                            <div className="text-xs font-medium text-slate-900 truncate">
                              {recip.name}
                            </div>
                            <div className="text-[10px] text-slate-500 truncate">
                              {recip.role}
                            </div>
                          </div>
                          <div
                            className={`w-4 h-4 rounded flex items-center justify-center shrink-0 border ${
                              isChecked
                                ? 'bg-indigo-600 border-indigo-600 text-white'
                                : 'border-slate-300 bg-white'
                            }`}
                          >
                            {isChecked && <Check className="w-2.5 h-2.5" />}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Packaging Action Trigger */}
                <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-slate-100">
                  <span className="text-[11px] text-slate-500">
                    Symmetric ciphertext encrypted once with AES-256-GCM.
                  </span>
                  <PrimaryButton
                    icon={<Lock className="w-3.5 h-3.5" />}
                    onClick={handleCreatePackage}
                    loading={isPackaging}
                    disabled={selectedRecipientIds.length === 0}
                    data-tour-target="generate-package-btn"
                  >
                    Encrypt &amp; prepare distribution
                  </PrimaryButton>
                </div>

                {/* Package Confirmation Card */}
                {activePackage && activePackage.documentId === selectedDoc.id && (
                  <div className="p-4 rounded-xl bg-emerald-50/70 border border-emerald-200 text-xs text-emerald-950 space-y-2 mt-4">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold flex items-center gap-1.5 text-emerald-800">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        Distribution package ready
                      </span>
                      <span className="text-[10px] font-mono text-emerald-700 bg-white px-2 py-0.5 rounded border border-emerald-200">
                        {activePackage.packageId}
                      </span>
                    </div>
                    <p className="text-[11px] text-emerald-800 leading-normal">
                      The document has been securely locked for {activePackage.envelopes.length} recipients using NIST FIPS 203 key encapsulation.
                    </p>
                    <div className="pt-2 flex flex-wrap items-center justify-between gap-2 border-t border-emerald-200/80">
                      <div className="text-[10px] text-emerald-800 font-medium">
                        {exportMessage || 'Portable .sihpkg container is safe for untrusted transport.'}
                      </div>
                      <div className="flex items-center gap-2">
                        <SecondaryButton
                          size="sm"
                          icon={<Download className="w-3.5 h-3.5" />}
                          onClick={handleExportSihpkg}
                          disabled={isExporting}
                        >
                          {isExporting ? 'Preparing secure package...' : 'Export .sihpkg'}
                        </SecondaryButton>
                        <SecondaryButton
                          size="sm"
                          icon={<ArrowRight className="w-3.5 h-3.5" />}
                          onClick={onNavigateToDecrypt}
                        >
                          Go to Decrypt
                        </SecondaryButton>
                      </div>
                    </div>
                  </div>
                )}

                {/* Technical details disclosure */}
                {activePackage && (
                  <TechnicalDetails title="Container metadata & key encapsulation envelopes">
                    <KeyValueRow label="Package ID" value={activePackage.packageId} />
                    <KeyValueRow label="Original Document Hash (SHA-256)" value={activePackage.originalDocumentHashSha256} />
                    <KeyValueRow label="IV (Hex)" value={activePackage.ivHex} />
                    <KeyValueRow label="GCM Tag (Hex)" value={activePackage.tagHex} />
                    <div className="pt-2">
                      <span className="text-[11px] font-semibold text-slate-700 block mb-1">
                        Encapsulated Envelopes ({activePackage.envelopes.length}):
                      </span>
                      {activePackage.envelopes.map((env) => (
                        <div key={env.recipientId} className="p-2 bg-slate-50 rounded border border-slate-200 mb-1.5 text-[10px]">
                          <div className="flex justify-between font-semibold text-slate-800">
                            <span>{env.recipientName}</span>
                            <span>{env.kemAlgorithm}</span>
                          </div>
                          <div className="text-slate-500 truncate mt-0.5">
                            Wrapped CEK: {env.wrappedCekBase64.slice(0, 32)}...
                          </div>
                        </div>
                      ))}
                    </div>
                  </TechnicalDetails>
                )}
              </div>
            </Section>
          ) : (
            <EmptyState
              icon={<FileText className="w-8 h-8" />}
              title="No document selected"
              description="Select a document on the left to configure multi-recipient distribution."
            />
          )}
        </div>
      </div>

      {/* Upload Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
          <div className="max-w-lg w-full bg-white rounded-xl shadow-xl border border-slate-200 p-6 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <h3 className="text-sm font-semibold text-slate-900">Upload new document</h3>
              <button
                onClick={() => setShowUploadModal(false)}
                className="p-1 text-slate-400 hover:text-slate-700 rounded cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Format Toggle: Real PDF vs Text */}
            <div className="flex items-center gap-2 p-1 bg-slate-100 rounded-lg border border-slate-200">
              <button
                type="button"
                onClick={() => setIsPdfUpload(true)}
                className={`flex-1 py-1.5 px-3 rounded-md text-xs font-medium transition-colors ${
                  isPdfUpload
                    ? 'bg-white text-slate-900 shadow-2xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Upload Binary PDF (.pdf)
              </button>
              <button
                type="button"
                onClick={() => setIsPdfUpload(false)}
                className={`flex-1 py-1.5 px-3 rounded-md text-xs font-medium transition-colors ${
                  !isPdfUpload
                    ? 'bg-white text-slate-900 shadow-2xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Raw Text Document
              </button>
            </div>

            <form onSubmit={handleUploadSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-700 font-medium mb-1">Document Title</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder={isPdfUpload ? 'e.g. Critical Defense Evaluation 2026' : 'e.g. Strategic Evaluation Report 2026'}
                  className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                />
              </div>

              <div>
                <label className="block text-slate-700 font-medium mb-1">Classification Level</label>
                <select
                  value={newClassification}
                  onChange={(e: any) => setNewClassification(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                >
                  <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                  <option value="SECRET">SECRET</option>
                  <option value="TOP SECRET // SCI">TOP SECRET // SCI</option>
                </select>
              </div>

              {isPdfUpload ? (
                <div>
                  <label className="block text-slate-700 font-medium mb-1">Select PDF File (Binary Stream Preserved)</label>
                  <div className="border-2 border-dashed border-slate-200 hover:border-slate-300 rounded-xl p-4 text-center bg-slate-50/60 relative">
                    <input
                      type="file"
                      accept=".pdf,application/pdf"
                      required={isPdfUpload}
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) handlePdfFileSelection(file);
                      }}
                      className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                    />
                    <FileUp className="w-6 h-6 text-slate-400 mx-auto mb-1.5" />
                    {uploadedPdfBytes ? (
                      <div className="space-y-0.5">
                        <div className="font-semibold text-emerald-800 flex items-center justify-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                          <span>{pdfFileName}</span>
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono">
                          {(pdfFileSize / 1024).toFixed(1)} KB &bull; %PDF Header Verified
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-0.5">
                        <div className="text-xs font-semibold text-slate-700">Click or drop a PDF here</div>
                        <div className="text-[11px] text-slate-400">Magic header %PDF-1.x verified in memory</div>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div>
                  <label className="block text-slate-700 font-medium mb-1">Document Content</label>
                  <textarea
                    required
                    rows={5}
                    value={newText}
                    onChange={(e) => setNewText(e.target.value)}
                    placeholder="Paste document body text here..."
                    className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                  />
                </div>
              )}

              {uploadError && (
                <div className="p-2.5 rounded-lg bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
                  <span>{uploadError}</span>
                </div>
              )}

              <div className="pt-2 flex justify-end gap-2">
                <SecondaryButton size="sm" type="button" onClick={() => setShowUploadModal(false)}>
                  Cancel
                </SecondaryButton>
                <PrimaryButton size="sm" type="submit">
                  Save &amp; Ingest
                </PrimaryButton>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageShell>
  );
};
