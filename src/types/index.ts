/**
 * Core type definitions for Post-Quantum Cryptographic Attribution
 * and Immutable Decryption Provenance System.
 */

export type UiMode = 'workstation' | 'guided';

export interface EncryptedKeystoreEnvelope {
  saltHex: string;
  ivHex: string;
  encryptedKemSecretBase64: string;
  encryptedDsaSecretBase64: string;
  kdf: 'PBKDF2-SHA256-100K';
  cipher: 'AES-256-GCM';
}

export interface RecipientKeyMetadata {
  kemAlgorithm: 'ML-KEM-768';
  kemPublicKeyHex: string;
  kemSecretKeyHex?: string; // Volatile unlocked state
  dsaAlgorithm: 'ML-DSA-65';
  dsaPublicKeyHex: string;
  dsaSecretKeyHex?: string; // Volatile unlocked state
  encryptedKeystore?: EncryptedKeystoreEnvelope; // Encrypted at rest
  keyFingerprint: string;
  registeredAt?: number;
}

export interface Recipient {
  id: string;
  name: string;
  role: string;
  organization: string;
  clearanceLevel: 'TOP SECRET // SCI' | 'SECRET' | 'CONFIDENTIAL' | 'RESTRICTED';
  avatarInitials: string;
  isUnlocked?: boolean;
  status?: string;
  distributionStatus?: string;
  createdAt?: number;
  keys: RecipientKeyMetadata;
}

export interface RecipientEnvelope {
  recipientId: string;
  recipientName: string;
  kemCiphertextBase64: string;
  wrappedCekBase64: string;
  kemAlgorithm: 'ML-KEM-768';
  envelopeId?: string;
  publicKeyFingerprint?: string;
  status?: 'AUTHORIZED' | 'REVOKED';
}

export type PackageLifecycleState = 'IMPORTED' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';

export interface EncryptedPackage {
  packageId: string;
  documentId: string;
  documentTitle: string;
  classification: string;
  version: number;
  originalDocumentHashSha256: string;
  ciphertextBase64: string;
  ivHex: string;
  tagHex: string;
  envelopes: RecipientEnvelope[];
  senderId: string;
  senderName: string;
  createdAt: number;
  isPdf?: boolean;
  mimeType?: string;
  filename?: string;
  fileSizeBytes?: number;
  distributionId?: string;
  lifecycleState?: PackageLifecycleState;
  importedAt?: number;
  isImported?: boolean;
  trackingStatus?: 'TRACKED' | 'TRACKING_FAILED';
  trackingError?: string;
}

export interface SihpkgRecipientEntry {
  recipientId: string;
  recipientName: string;
  envelopeId: string;
  publicKeyFingerprint: string;
  kemAlgorithm: 'ML-KEM-768';
  kemCiphertextBase64: string;
  wrappedCekBase64: string;
  status: 'AUTHORIZED' | 'REVOKED';
}

export interface SihpkgManifest {
  format: 'SIHPKG';
  version: 1;
  packageId: string;
  distributionId: string;
  createdAt: number;
  sender: {
    senderId: string;
    senderName: string;
  };
  document: {
    documentId: string;
    documentTitle: string;
    filename: string;
    mimeType: string;
    sizeBytes: number;
    classification: string;
    originalDocumentHashSha256: string;
  };
  encryption: {
    algorithm: 'AES-256-GCM';
    ivHex: string;
    tagHex: string;
    aadBinding: string;
    aadString?: string;
  };
  recipients: SihpkgRecipientEntry[];
  integrity: {
    manifestHashSha256: string;
    payloadHashSha256: string;
    packageHashSha256: string;
  };
}

export type SihpkgValidationStatus =
  | 'VALID'
  | 'PACKAGE_QUARANTINED'
  | 'PACKAGE_INTEGRITY_FAILURE'
  | 'PAYLOAD_INTEGRITY_FAILURE'
  | 'DOCUMENT_BINDING_FAILURE'
  | 'ENVELOPE_INTEGRITY_FAILURE'
  | 'DISTRIBUTION_BINDING_FAILURE'
  | 'UNSUPPORTED_VERSION'
  | 'CORRUPTED_PACKAGE';

export interface PackageValidationStep {
  name: string;
  passed: boolean;
  detail: string;
}

export interface PackageValidationResult {
  isValid: boolean;
  status: SihpkgValidationStatus;
  errorMessage?: string;
  manifest?: SihpkgManifest;
  package?: EncryptedPackage;
  rawBinary?: Uint8Array;
  validationSteps: PackageValidationStep[];
  recipientAuthorization?: {
    recipientId: string;
    recipientName: string;
    status: 'AUTHORIZED' | 'REVOKED' | 'UNAUTHORIZED';
    canDecrypt: boolean;
    reason: string;
  };
}

export * from './audit';

export interface PackageAuditEvent {
  eventId: string;
  eventType:
    | 'PACKAGE_EXPORTED'
    | 'PACKAGE_IMPORTED'
    | 'PACKAGE_VALIDATION_FAILED'
    | 'PACKAGE_REJECTED'
    | 'PACKAGE_DECRYPTED';
  timestamp: number;
  packageId: string;
  distributionId?: string;
  documentId?: string;
  recipientId?: string;
  status: 'SUCCESS' | 'FAILED' | 'REJECTED';
  details: string;
}

export interface DecryptionEventPayload {
  eventId: string;
  documentId: string;
  documentTitle: string;
  documentHashSha256: string;
  packageHashSha256: string;
  recipientId: string;
  recipientName: string;
  recipientPubkeyFingerprint: string;
  sessionId: string;
  watermarkId: string;
  watermarkCommitment: string;
  timestampEpochMs: number;
  clientMetadata: {
    terminalId: string;
    runtimeSecurity: string;
  };
}

export interface DecryptionEvent extends DecryptionEventPayload {
  signatureAlgorithm: 'ML-DSA-65';
  recipientSignatureBase64: string;
  blockHeight?: number;
  txHash?: string;
  status: 'MEMPOOL' | 'COMMITTED';
}

export interface WatermarkPayload {
  syncHeader: number; // 0xA55A
  sessionId: string;
  watermarkId: string;
  recipientId: string;
  recipientFingerprint: string;
  timestamp: number;
  eccChecksum: number;
  documentHashSha256?: string;
  watermarkCommitment?: string;
  authTag?: string;
}

export interface ValidatorNode {
  id: string;
  name: string;
  role: string;
  location: string;
  status: 'ONLINE' | 'VALIDATING' | 'SYNCED' | 'OFFLINE';
  blocksValidated: number;
  publicVerificationKeyHex: string;
}

export interface LedgerBlock {
  height: number;
  timestamp: number;
  previousHash: string;
  blockHash: string;
  merkleRoot: string;
  transactions: DecryptionEvent[];
  validatorSignatures: Array<{
    validatorId: string;
    validatorName: string;
    signatureHex: string;
  }>;
  stateRoot: string;
}

export type ForensicAttributionVerdict =
  | 'CONFIRMED_LEAK_SOURCE'
  | 'VERIFIED'
  | 'NO_WATERMARK'
  | 'INVALID_PDF'
  | 'CORRUPTED_WATERMARK'
  | 'TAMPERED_WATERMARK'
  | 'NO_MATCHING_EVENT'
  | 'DOCUMENT_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'LEDGER_INVALID'
  | 'EVIDENCE_MISMATCH'
  | 'ANALYSIS_ERROR'
  | 'UNREGISTERED_EVENT'
  | 'FAILED_EXTRACTION';

export interface ForensicCaseRecord {
  caseId: string;
  analyzedFileName: string;
  fileSizeBytes: number;
  resultVerdict: ForensicAttributionVerdict;
  verificationStatus: 'VERIFIED' | 'FAILED';
  attributedRecipientName?: string;
  attributedRecipientId?: string;
  eventId?: string;
  watermarkId?: string;
  blockHeight?: number;
  analyzedAt: number;
  failureReason?: string;
  certificateId?: string;
}

export interface ForensicAttributionReport {
  reportId: string;
  analyzedAt: number;
  watermarkExtracted: boolean;
  watermarkPayload?: WatermarkPayload;
  matchedEvent?: DecryptionEvent;
  matchedBlock?: LedgerBlock;
  merkleProofValid: boolean;
  pqcSignatureValid: boolean;
  ledgerIntegrityValid: boolean;
  attributedRecipient?: Recipient;
  attributionVerdict: ForensicAttributionVerdict;
  verificationStatus: 'VERIFIED' | 'FAILED';
  verdict: ForensicAttributionVerdict;
  confidenceScore: number; // 0 to 100
  evidenceChain: Array<{
    step: string;
    description: string;
    status: 'VERIFIED' | 'WARNING' | 'FAILED';
    technicalDetail: string;
  }>;
  caseId?: string;
  certificate?: ForensicAttributionCertificate;
}

export interface ForensicAttributionCertificate {
  certificateId: string; // e.g. CERT-2026-00421-7F91
  caseId: string; // e.g. CASE-2026-00421
  issuedAtEpochMs: number;
  issuedAtIso: string;
  verdict: 'VERIFIED' | 'FAILED' | ForensicAttributionVerdict;
  attributionStatement: string;
  disclaimer: string;
  document: {
    documentId: string;
    title: string;
    sha256Hash: string;
    classification?: string;
  };
  investigatedArtifact: {
    filename: string;
    sizeBytes: number;
    sha256Hash: string;
    watermarkExtracted: boolean;
    watermarkId?: string;
    extractionSource: 'PDF' | 'TEXT';
  };
  attributionTarget: {
    recipientId: string;
    name: string;
    organization: string;
    role: string;
    clearanceLevel: string;
    publicKeyFingerprint: string;
    algorithm: string;
  };
  decryptionSession: {
    sessionId: string;
    eventId: string;
    timestampEpochMs: number;
    timestampIso: string;
    terminalId: string;
    runtimeSecurity: string;
  };
  cryptographicProof: {
    signatureAlgorithm: 'ML-DSA-65';
    recipientSignatureBase64: string;
    canonicalMessage: string;
    signatureVerified: boolean;
    watermarkCommitment: string;
    merkleRoot: string;
    merkleProofValid: boolean;
    ledgerBlockHeight: number;
    blockHash: string;
    previousBlockHash: string;
    validatorQuorum: {
      required: number;
      actual: number;
      quorumSatisfied: boolean;
      validators: Array<{
        validatorId: string;
        validatorName: string;
        signatureHex: string;
      }>;
    };
  };
  evidenceChain: Array<{
    step: string;
    description: string;
    status: 'VERIFIED' | 'WARNING' | 'FAILED';
    technicalDetail: string;
  }>;
  certificateHashSha256: string;
  issuerAuthority: {
    systemName: string;
    specification: string;
    securityStandards: string[];
  };
}

export interface CertificateVerificationResult {
  valid: boolean;
  tamperDetected: boolean;
  tamperReason?: string;
  calculatedHashSha256: string;
  storedHashSha256: string;
  hashMatch: boolean;
  signatureValid: boolean;
  ledgerValid: boolean;
  quorumValid: boolean;
  documentBindingValid: boolean;
  details: Array<{
    check: string;
    passed: boolean;
    message: string;
  }>;
}

export interface ClassifiedDocument {
  id: string;
  title: string;
  classification: 'TOP SECRET // SCI' | 'SECRET' | 'CONFIDENTIAL';
  caveats: string;
  originatingOffice: string;
  summary: string;
  rawText: string;
  visualPages: string[]; // SVGs / Canvas Data URLs
  createdAt: number;
  // Binary PDF representation
  isPdf?: boolean;
  mimeType?: string; // e.g. 'application/pdf'
  filename?: string;
  fileSizeBytes?: number;
  pdfBytes?: Uint8Array; // In-memory canonical binary buffer
}

// Assignment & Notification foundation models
export * from './assignment';
// Signed offline receipt (.sihrcpt) models
export * from './receipt';
