/**
 * AEGIS-PQC Versioned Offline Decryption Receipt (.sihrcpt) Data Models.
 * 
 * Provides offline verifiable cryptographic proof that an authorized recipient
 * decrypted an encrypted document package at a specific time and recorded the
 * decryption event into the air-gapped provenance ledger, signed with their
 * post-quantum ML-DSA-65 digital signature.
 * 
 * Cryptographic Invariant:
 * Receipts NEVER contain original PDF bytes, decrypted plaintext, symmetric CEK,
 * or private keys. They contain only provenance metadata and cryptographic signatures.
 */

export const SIHRCPT_MAGIC = 'SIHRCPT01' as const;
export const SIHRCPT_VERSION = 1 as const;

export interface ReceiptPayload {
  magic: typeof SIHRCPT_MAGIC;
  version: typeof SIHRCPT_VERSION;
  receiptId: string;
  assignmentId?: string;
  distributionId?: string;
  packageId: string;
  documentId: string;
  documentTitle: string;
  classification: string;
  recipientId: string;
  recipientName: string;
  recipientFingerprint: string;
  decryptionTimestamp: number;
  decryptionEventId: string;
  blockHeight: number;
  blockHash: string;
  watermarkId: string;
  watermarkCommitment: string;
  createdAt: number;
  clientMetadata?: {
    terminalId?: string;
    runtimeSecurity?: string;
  };
}

export interface SignedOfflineReceipt extends ReceiptPayload {
  signatureAlgorithm: 'ML-DSA-65';
  signatureBase64: string;
  signerPublicKeyHex: string;
}

export type ReceiptAssuranceTier =
  | 'AUTHENTIC_AND_LEDGER_CONFIRMED'
  | 'SIGNATURE_VALID_UNCONFIRMED_LEDGER'
  | 'UNTRUSTED_OR_TAMPERED'
  | 'INVALID_STRUCTURE';

export interface ReceiptVerificationResult {
  valid: boolean;
  receipt?: SignedOfflineReceipt;
  signatureValid: boolean;
  identityBound: boolean;
  ledgerVerified: boolean;
  registeredRecipientFound: boolean;
  provenanceAssurance: ReceiptAssuranceTier;
  assuranceSummary: string;
  signerRecipient?: {
    id: string;
    name: string;
    role: string;
    clearanceLevel: string;
    avatarInitials: string;
  };
  errors: string[];
  warnings: string[];
}

