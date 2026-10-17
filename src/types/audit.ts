/**
 * Security & Activity Audit Center Types.
 * Strictly adheres to OWASP Logging guidelines, RFC 5424 structured logging,
 * and NIST CSF 2.0 continuous operational visibility principles.
 */

export type AuditSeverity = 'INFO' | 'NOTICE' | 'WARNING' | 'ERROR' | 'CRITICAL';

export type AuditCategory =
  | 'AUTHENTICATION'
  | 'AUTHORIZATION'
  | 'DOCUMENT'
  | 'CRYPTOGRAPHY'
  | 'DISTRIBUTION'
  | 'PACKAGE'
  | 'DECRYPTION'
  | 'WATERMARK'
  | 'PROVENANCE'
  | 'LEDGER'
  | 'FORENSICS'
  | 'CERTIFICATE'
  | 'SYSTEM'
  | 'SECURITY'
  | 'ADMINISTRATION';

export type AuditOutcome = 'SUCCESS' | 'FAILURE' | 'DENIED' | 'REJECTED' | 'PENDING';

export type AuditEventType =
  // Document Events
  | 'DOCUMENT_CREATED'
  | 'DOCUMENT_IMPORTED'
  | 'DOCUMENT_HASHED'
  | 'DOCUMENT_ENCRYPTED'
  | 'DOCUMENT_EXPORTED'
  | 'DOCUMENT_ACCESSED'
  | 'DOCUMENT_DECRYPTED'
  | 'DOCUMENT_REVOKED'
  | 'DOCUMENT_DELETED'
  // Distribution Events
  | 'DISTRIBUTION_CREATED'
  | 'RECIPIENT_AUTHORIZED'
  | 'RECIPIENT_REVOKED'
  | 'RECIPIENT_ADDED'
  | 'RECIPIENT_REMOVED'
  | 'DISTRIBUTION_EXPORTED'
  | 'DISTRIBUTION_TRACKING_FAILED'
  // Package Events (.sihpkg)
  | 'PACKAGE_EXPORTED'
  | 'PACKAGE_IMPORTED'
  | 'PACKAGE_VALIDATION_STARTED'
  | 'PACKAGE_VALIDATION_SUCCESS'
  | 'PACKAGE_VALIDATION_FAILED'
  | 'PACKAGE_REJECTED'
  | 'PACKAGE_INTEGRITY_FAILURE'
  | 'PAYLOAD_INTEGRITY_FAILURE'
  | 'ENVELOPE_INTEGRITY_FAILURE'
  | 'PACKAGE_CORRUPTION_DETECTED'
  // Authorization & Session Events
  | 'AUTHORIZATION_GRANTED'
  | 'AUTHORIZATION_DENIED'
  | 'UNAUTHORIZED_ACCESS_ATTEMPT'
  | 'REVOKED_ACCESS_ATTEMPT'
  | 'SESSION_UNLOCKED'
  | 'SESSION_LOCKED'
  // Decryption Events
  | 'DECRYPTION_REQUESTED'
  | 'DECRYPTION_AUTHORIZED'
  | 'DECRYPTION_DENIED'
  | 'DECRYPTION_FAILED'
  | 'DECRYPTION_SUCCESS'
  | 'PACKAGE_DECRYPTED' // Backward compatibility with PackageAuditEvent
  // Watermark Events
  | 'WATERMARK_GENERATED'
  | 'WATERMARK_EMBEDDED'
  | 'WATERMARK_EXTRACTED'
  | 'WATERMARK_VERIFIED'
  | 'WATERMARK_INVALID'
  | 'WATERMARK_DOCUMENT_MISMATCH'
  // Cryptographic Events
  | 'AAD_VALIDATION_SUCCESS'
  | 'AAD_VALIDATION_FAILURE'
  | 'ML_KEM_DECAPSULATION_SUCCESS'
  | 'ML_KEM_DECAPSULATION_FAILURE'
  | 'AES_GCM_DECRYPT_SUCCESS'
  | 'AES_GCM_DECRYPT_FAILURE'
  | 'ML_DSA_SIGNATURE_VALID'
  | 'ML_DSA_SIGNATURE_INVALID'
  | 'HASH_VALIDATION_SUCCESS'
  | 'HASH_VALIDATION_FAILURE'
  // DLT & Consensus Events
  | 'PROVENANCE_EVENT_CREATED'
  | 'PROVENANCE_EVENT_SIGNED'
  | 'DLT_TRANSACTION_SUBMITTED'
  | 'DLT_TRANSACTION_COMMITTED'
  | 'BLOCK_CREATED'
  | 'BLOCK_VERIFIED'
  | 'BLOCK_INTEGRITY_FAILURE'
  | 'MERKLE_VERIFICATION_FAILURE'
  | 'VALIDATOR_ATTESTATION_RECEIVED'
  | 'VALIDATOR_QUORUM_SATISFIED'
  | 'VALIDATOR_QUORUM_FAILED'
  // Forensic Investigation Events
  | 'FORENSIC_INVESTIGATION_STARTED'
  | 'WATERMARK_FOUND'
  | 'RECIPIENT_IDENTIFIED'
  | 'DOCUMENT_BINDING_VERIFIED'
  | 'FORENSIC_ATTRIBUTION_VERIFIED'
  | 'FORENSIC_ATTRIBUTION_FAILED'
  | 'EVIDENCE_MISMATCH'
  // Attribution Certificate Events
  | 'CERTIFICATE_GENERATED'
  | 'CERTIFICATE_EXPORTED'
  | 'CERTIFICATE_IMPORTED'
  | 'CERTIFICATE_VERIFIED'
  | 'CERTIFICATE_VERIFICATION_FAILED'
  | 'CERTIFICATE_INTEGRITY_FAILURE'
  // Security Attack & Tampering Events
  | 'PACKAGE_TAMPERING_DETECTED'
  | 'ENVELOPE_SUBSTITUTION_DETECTED'
  | 'DOCUMENT_MISMATCH_DETECTED'
  | 'WATERMARK_REPLAY_DETECTED'
  | 'INVALID_SIGNATURE_DETECTED'
  | 'INVALID_CERTIFICATE_DETECTED'
  | 'QUORUM_FAILURE'
  | 'UNAUTHORIZED_DECRYPTION_ATTEMPT'
  | 'REVOKED_DECRYPTION_ATTEMPT'
  | 'CORRUPTED_PACKAGE_DETECTED'
  | 'AUDIT_INTEGRITY_ALERT'
  // Incident Lifecycle & Response Events
  | 'INCIDENT_CREATED'
  | 'INCIDENT_STATUS_UPDATED'
  | 'INCIDENT_ACTION_EXECUTED'
  | 'INCIDENT_RESOLVED'
  // Dossier Reporting & Verification Events
  | 'DOSSIER_GENERATED'
  | 'DOSSIER_EXPORTED'
  | 'DOSSIER_VERIFIED'
  | 'DOSSIER_VERIFICATION_FAILED';

export interface AuditActor {
  type: 'USER' | 'SYSTEM' | 'VALIDATOR' | 'UNKNOWN';
  id?: string;
  displayName?: string;
}

export interface AuditResource {
  type:
    | 'DOCUMENT'
    | 'PACKAGE'
    | 'DISTRIBUTION'
    | 'RECIPIENT'
    | 'SESSION'
    | 'INVESTIGATION'
    | 'CERTIFICATE'
    | 'LEDGER'
    | 'AUDIT_STORE';
  id?: string;
}

export interface SafeAuditMetadata {
  [key: string]: string | number | boolean | null | undefined;
}

/**
 * Unified, canonical Audit Event Model with cryptographic hash chaining.
 * Prohibits logging of private keys, CEKs, passphrases, or raw document content.
 */
export interface AuditEvent {
  eventId: string;
  timestamp: string; // ISO 8601 UTC
  timestampEpochMs: number;
  timestampSource?: 'LOCAL_RUNTIME' | 'NETWORK_TIME';

  eventType: AuditEventType;
  severity: AuditSeverity;
  category: AuditCategory;

  actor: AuditActor;
  resource: AuditResource;
  action: string;
  outcome: AuditOutcome;

  description: string;
  reason?: string;

  // Correlated Business & Cryptographic Entities
  documentId?: string;
  distributionId?: string;
  packageId?: string;
  recipientId?: string;
  sessionId?: string;
  transactionId?: string;
  blockIndex?: number;
  certificateId?: string;
  caseId?: string;
  watermarkId?: string;

  correlationId?: string;

  // Cryptographic Tamper-Evident Hash Chain
  eventHash?: string;
  previousEventHash?: string;

  // Immutable Provenance & DLT Anchoring
  dltAnchored?: boolean;
  dltTransactionId?: string;
  dltBlockHeight?: number;

  metadata?: SafeAuditMetadata;
}

/**
 * Audit Hash Chain Verification Result
 */
export interface AuditChainVerificationResult {
  valid: boolean;
  eventsChecked: number;
  firstInvalidEvent: string | null;
  reason?: string;
  chainRootHash?: string;
  latestEventHash?: string;
  anchoredEventsCount: number;
}

/**
 * Rule-Based Threat Alert Derived from Audit Log Correlation
 */
export interface SecurityAlert {
  alertId: string;
  severity: 'CRITICAL' | 'WARNING' | 'NOTICE';
  title: string;
  summary: string;
  threatType:
    | 'REPEATED_UNAUTHORIZED_ACCESS'
    | 'PACKAGE_TAMPERING_BURST'
    | 'VALIDATOR_QUORUM_FAILURE'
    | 'AUDIT_CHAIN_TAMPER'
    | 'DOCUMENT_FORGERY_ATTEMPT';
  detectedAt: number;
  triggerEventIds: string[];
  targetResourceId?: string;
  targetRecipientId?: string;
  occurrenceCount: number;
}

/**
 * Query & Filter Parameters for Audit Center
 */
export interface AuditQueryFilter {
  category?: AuditCategory | 'ALL';
  severity?: AuditSeverity | 'ALL';
  outcome?: AuditOutcome | 'ALL';
  actorId?: string;
  resourceType?: AuditResource['type'] | 'ALL';
  resourceId?: string;
  documentId?: string;
  recipientId?: string;
  correlationId?: string;
  dltStatus?: 'ALL' | 'ANCHORED' | 'LOCAL_ONLY';
  searchQuery?: string;
  timeRange?: 'TODAY' | 'LAST_24_HOURS' | 'LAST_7_DAYS' | 'LAST_30_DAYS' | 'ALL';
}
