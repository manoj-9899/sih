/**
 * Security Incident Engine Types & Data Model.
 * 
 * Defines typed models for stateful incident management, configurable detection rules,
 * evidence tracking, and investigator response workflows.
 * 
 * Strict Reality Boundary:
 * All incidents represent host-workstation security evaluations within the local
 * browser-based cryptographic enclave. Inferred malicious intent is explicitly
 * separated from mathematical cryptographic integrity failures.
 */

export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * Incident Confidence:
 * - CERTAIN: Supported by mathematical proof (AES-GCM tag mismatch, hash divergence, signature verification failure).
 * - HIGH: Correlated by deterministic rule with strong identity/package binding.
 * - MEDIUM: Pattern detected across heuristic thresholds (e.g., repeated denials).
 * - LOW: Inferred anomaly with limited telemetry.
 */
export type IncidentConfidence = 'LOW' | 'MEDIUM' | 'HIGH' | 'CERTAIN';

export type IncidentStatus =
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'RESOLVED'
  | 'FALSE_POSITIVE';

export type IncidentType =
  | 'REPEATED_UNAUTHORIZED_ACCESS'
  | 'PACKAGE_INTEGRITY_TAMPER'
  | 'WATERMARK_DOCUMENT_FORGERY'
  | 'DLT_QUORUM_FAILURE'
  | 'AUDIT_CHAIN_INTEGRITY_COMPROMISED';

export type ContainmentActionType =
  | 'REVOKE_RECIPIENT'
  | 'FLAG_PACKAGE_ISOLATED'
  | 'RECORD_FORENSIC_SNAPSHOT'
  | 'EXPORT_INCIDENT_DOSSIER'
  | 'ADD_INVESTIGATION_NOTE';

export interface IncidentEvidenceItem {
  eventId: string;
  timestampEpochMs: number;
  eventType: string;
  category: string;
  severity: string;
  outcome: string;
  actorId?: string;
  resourceId?: string;
  summary: string;
}

export interface IncidentResponseAction {
  actionId: string;
  actionType: ContainmentActionType;
  executedAt: number;
  actorId: string;
  actorDisplayName?: string;
  details: string;
  outcome: 'SUCCESS' | 'FAILED';
  errorMessage?: string;
}

export interface InvestigatorNote {
  noteId: string;
  authorId: string;
  authorDisplayName: string;
  timestamp: number;
  text: string;
}

export interface IncidentResolution {
  resolvedAt: number;
  resolvedBy: string;
  reason: string;
  resolutionCategory: 'CONTAINED' | 'MITIGATED' | 'FALSE_POSITIVE_CONFIRMED' | 'ACCEPTED_RISK';
}

export interface SecurityIncident {
  incidentId: string; // Formatted e.g. INC-2026-AUTH-A1B2
  correlationKey: string; // Deduplication key (e.g. AUTH-DENIED:REC-ALICE-01)
  incidentType: IncidentType;
  title: string;
  description: string;
  severity: IncidentSeverity;
  confidence: IncidentConfidence;
  status: IncidentStatus;

  // Detection Rule Metadata
  ruleId: string;
  detectionRuleName: string;
  thresholdApplied: {
    minOccurrences: number;
    timeWindowMs: number;
    actualOccurrences: number;
  };

  firstObservedAt: number;
  lastObservedAt: number;

  // Correlated Target Entities
  affectedRecipientId?: string;
  affectedRecipientName?: string;
  affectedDocumentId?: string;
  affectedPackageId?: string;
  affectedTransactionId?: string;
  affectedBlockIndex?: number;

  // Evidence references (bound to genuine audit log records)
  evidenceEventIds: string[];
  evidenceDigest: string; // SHA-256 consistency check over sorted evidence IDs

  investigatorNotes: InvestigatorNote[];
  responseActions: IncidentResponseAction[];
  resolution?: IncidentResolution;
}

export interface DetectionRuleConfig {
  ruleId: string;
  name: string;
  description: string;
  enabled: boolean;
  incidentType: IncidentType;
  defaultSeverity: IncidentSeverity;
  defaultConfidence: IncidentConfidence;
  minOccurrences: number;
  timeWindowMs: number;
}

export interface IncidentEngineMetrics {
  totalIncidents: number;
  openIncidents: number;
  investigatingIncidents: number;
  resolvedIncidents: number;
  falsePositives: number;
  criticalIncidents: number;
  highIncidents: number;
  lastEvaluationTimestamp: number;
}
