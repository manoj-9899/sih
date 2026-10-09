/**
 * Incident Reporting & Forensic Dossier Types.
 * 
 * Defines typed models for structured investigation dossiers,
 * issuance-time vs live verification comparisons, PDF & JSON representations,
 * evidence reference audits, and strict legal/security disclaimer invariants.
 */

export interface DossierEvidenceRecord {
  eventId: string;
  timestampEpochMs: number;
  timestampIso: string;
  eventType: string;
  category: string;
  severity: string;
  outcome: string;
  actor: { type: string; id?: string; displayName?: string };
  resource: { type: string; id?: string };
  summary: string;
  eventHashSha256: string;
  dltAnchored: boolean;
  dltBlockHeight?: number;
  verifiedInAuditChain: boolean;
}

export interface DossierProvenanceContext {
  associatedCertificateId?: string;
  certificateAttributionStatement?: string;
  watermarkCommitmentHex?: string;
  watermarkId?: string;
  dltTransactionId?: string;
  dltBlockHeight?: number;
  blockHash?: string;
  merkleRoot?: string;
  validatorQuorumCount?: number;
  merkleProofValid?: boolean;
}

export interface IssuanceVerificationSnapshot {
  auditChainValid: boolean;
  auditChainEventsChecked: number;
  auditChainHeadDigest: string;
  evidenceDigestConsistency: string; // SHA-256 over sorted event IDs
  allEvidenceEventsExisted: boolean;
  timestampEpochMs: number;
}

export interface DossierVerificationResult {
  valid: boolean;
  tamperDetected: boolean;
  tamperReason?: string;

  // Canonical JSON content digest verification
  calculatedDigestSha256: string;
  storedDigestSha256: string;
  digestMatch: boolean;

  // PDF verification boundary status
  pdfDigestSha256?: string;
  pdfVerificationNote: string;

  // Separate Issuance vs Live verification states
  issuanceVerification: IssuanceVerificationSnapshot;
  currentLiveVerification: {
    auditChainValid: boolean;
    auditChainEventsChecked: number;
    auditChainHeadDigest: string;
    allEvidenceEventsMatchLiveStore: boolean;
    missingEventIds: string[];
    mismatchedEventIds: string[];
  };

  // Structured verification checklist
  checks: Array<{ check: string; passed: boolean; message: string }>;
}

export interface ForensicDossier {
  dossierId: string;              // e.g. DOSSIER-2026-F4A1B2
  sourceIncidentId: string;       // Linked Security Incident ID
  generatedAtEpochMs: number;
  generatedAtIso: string;
  generatedBy: { id: string; name: string; role: string };

  // 1. Incident Executive Summary
  incidentSummary: {
    incidentId: string;
    incidentType: string;
    severity: string;
    confidence: string;
    status: string;
    ruleId: string;
    detectionRuleName: string;
    firstObservedAtIso: string;
    lastObservedAtIso: string;
    description: string;
  };

  // 2. Correlated Target Entities
  affectedEntities: {
    recipientId?: string;
    recipientName?: string;
    documentId?: string;
    documentTitle?: string;
    packageId?: string;
    transactionId?: string;
    blockIndex?: number;
  };

  // 3. Evidence Timeline (Verified against raw audit log records)
  evidenceTimeline: DossierEvidenceRecord[];

  // 4. Issuance-Time Cryptographic Verification State
  issuanceVerification: IssuanceVerificationSnapshot;

  // 5. Forensic Provenance & Attribution (When Available)
  forensicProvenance?: DossierProvenanceContext;

  // 6. Response & Containment History
  responseHistory: {
    statusTransitions: Array<{ timestamp: number; from: string; to: string; author: string }>;
    containmentActions: Array<{ actionType: string; executedAt: number; actor: string; details: string; outcome: string }>;
    investigatorNotes: Array<{ timestamp: number; author: string; text: string }>;
    resolution?: { resolvedAt: number; resolvedBy: string; reason: string; resolutionCategory: string };
  };

  // 7. Boundaries & Limitations Statement (Strict Honesty)
  limitations: {
    missingEvidence: string[];
    simulatedInfrastructureNotice: string;
    intentDisclaimer: string;
  };

  // Optional PDF hash stored if PDF is built alongside JSON
  pdfDigestSha256?: string;

  // Canonical SHA-256 Digest of the dossier content (computed with this field excluded)
  dossierDigestSha256: string;
}
