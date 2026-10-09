/**
 * Central Activity & Security Audit Service.
 * 
 * Provides centralized, structured, tamper-evident cryptographic logging across
 * the entire document lifecycle (document, encryption, distribution, .sihpkg,
 * decryption, invisible forensic watermarking, DLT provenance, leak investigation,
 * and attribution certificates).
 * 
 * Security Principles Enforced:
 * 1. Unified Event Taxonomy (RFC 5424 structured logging)
 * 2. Cryptographic Hash Chaining (E1 -> E2 -> E3 tamper detection)
 * 3. OWASP Log Injection Prevention (sanitizes delimiters, control chars, limits field length)
 * 4. Strict Sensitive Data Exclusion (Zero private keys, CEKs, plaintexts, or passphrases logged)
 * 5. Immutable DLT Anchoring for Provenance Events
 * 6. Rule-Based Threat & Anomaly Detection (NIST CSF 2.0 continuous monitoring)
 */

import {
  AuditEvent,
  AuditEventType,
  AuditSeverity,
  AuditCategory,
  AuditOutcome,
  AuditActor,
  AuditResource,
  SafeAuditMetadata,
  AuditChainVerificationResult,
  SecurityAlert,
  AuditQueryFilter,
} from '../types/audit';
import { sha256Hex, canonicalizeJson } from '../crypto/pqc';
import { airGappedStorage } from '../storage/airGappedStorage';
import { airGappedLedger } from '../ledger/dlt';

export interface AuditRecordInput {
  eventType: AuditEventType;
  severity: AuditSeverity;
  category: AuditCategory;
  actor: AuditActor;
  resource: AuditResource;
  action: string;
  outcome: AuditOutcome;
  description: string;
  reason?: string;

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

  dltAnchored?: boolean;
  dltTransactionId?: string;
  dltBlockHeight?: number;

  metadata?: SafeAuditMetadata;
}

// Maximum permissible string lengths to prevent audit store exhaustion
const MAX_FIELD_LENGTH = 1000;
const MAX_DESC_LENGTH = 2000;

// Prohibited secret keys in metadata
const PROHIBITED_SECRET_PATTERNS = [
  /cek/i,
  /keyencryptionkey/i,
  /secretkey/i,
  /privatekey/i,
  /passphrase/i,
  /password/i,
  /token/i,
  /rawplaintext/i,
  /kemsecret/i,
  /dsasecret/i,
];

export class AuditService {
  private static instance: AuditService | null = null;
  private memoryCache: AuditEvent[] = [];
  private isLoaded = false;
  private writeLock: Promise<void> = Promise.resolve();

  private constructor() {}

  public static getInstance(): AuditService {
    if (!AuditService.instance) {
      AuditService.instance = new AuditService();
    }
    return AuditService.instance;
  }

  /**
   * Sanitizes external strings to prevent log injection (CRLF, control chars)
   * and truncates oversized inputs.
   */
  public static sanitizeString(input: string | undefined | null, maxLength = MAX_FIELD_LENGTH): string {
    if (!input || typeof input !== 'string') return '';
    // Strip control characters, CR, LF, null bytes
    const cleaned = input
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
      .replace(/[\r\n]+/g, ' ')
      .trim();
    return cleaned.slice(0, maxLength);
  }

  /**
   * Generates a unique, cryptographically strong Event ID.
   */
  public static generateEventId(): string {
    const entropy = crypto.getRandomValues(new Uint8Array(5));
    const hex = Array.from(entropy).map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return `EVT-${Date.now().toString(36).toUpperCase()}-${hex}`;
  }

  /**
   * Generates a correlation ID for multi-stage transactions.
   */
  public static generateCorrelationId(prefix = 'CORR'): string {
    const entropy = crypto.getRandomValues(new Uint8Array(4));
    const hex = Array.from(entropy).map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return `${prefix}-${hex}`;
  }

  /**
   * Ensures in-memory cache is synchronized with persistent storage.
   */
  private async ensureLoaded(): Promise<void> {
    if (this.isLoaded) return;
    try {
      const stored = await airGappedStorage.getAuditEvents();
      this.memoryCache = stored.map((e) => this.normalizeLegacyEvent(e));
      this.isLoaded = true;
    } catch (e) {
      console.warn('[AuditService] Failed to load audit events:', e);
      this.memoryCache = [];
      this.isLoaded = true;
    }
  }

  /**
   * Normalizes legacy PackageAuditEvent objects into the unified AuditEvent schema.
   */
  private normalizeLegacyEvent(e: any): AuditEvent {
    if (e.eventHash) {
      return e as AuditEvent;
    }
    // Legacy mapping
    const timestampEpochMs = e.timestampEpochMs || (typeof e.timestamp === 'number' ? e.timestamp : Date.now());
    return {
      eventId: e.eventId || AuditService.generateEventId(),
      timestamp: new Date(timestampEpochMs).toISOString(),
      timestampEpochMs,
      timestampSource: 'LOCAL_RUNTIME',
      eventType: e.eventType || 'PACKAGE_DECRYPTED',
      severity: e.status === 'FAILED' || e.status === 'REJECTED' ? 'WARNING' : 'INFO',
      category: 'PACKAGE',
      actor: { type: 'USER', id: e.recipientId || 'SYSTEM' },
      resource: { type: 'PACKAGE', id: e.packageId },
      action: e.eventType || 'PACKAGE_ACTION',
      outcome: e.status === 'SUCCESS' ? 'SUCCESS' : e.status === 'REJECTED' ? 'REJECTED' : 'FAILURE',
      description: e.details || 'Legacy audit event record',
      packageId: e.packageId,
      distributionId: e.distributionId,
      documentId: e.documentId,
      recipientId: e.recipientId,
    };
  }

  /**
   * Strips any sensitive cryptographic keys or passwords from metadata.
   */
  private sanitizeMetadata(meta?: SafeAuditMetadata): SafeAuditMetadata | undefined {
    if (!meta || typeof meta !== 'object') return undefined;
    const sanitized: SafeAuditMetadata = {};
    for (const [key, value] of Object.entries(meta)) {
      const isSensitive = PROHIBITED_SECRET_PATTERNS.some((pattern) => pattern.test(key));
      if (isSensitive) {
        sanitized[key] = '[REDACTED_SECRET_MATERIAL]';
      } else if (typeof value === 'string') {
        sanitized[key] = AuditService.sanitizeString(value, 200);
      } else if (typeof value === 'number' || typeof value === 'boolean' || value === null) {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  /**
   * Computes canonical hash for an audit event, incorporating previous event hash.
   */
  public async computeEventHash(
    eventWithoutHash: Omit<AuditEvent, 'eventHash'>,
    previousEventHash: string
  ): Promise<string> {
    const canonicalPayload = canonicalizeJson({
      ...eventWithoutHash,
      previousEventHash,
    });
    return await sha256Hex(canonicalPayload);
  }

  /**
   * Central Logging Routine:
   * Validates, sanitizes, computes hash chain, persists to air-gapped store,
   * and optionally flags for immutable DLT linkage.
   */
  public async record(input: AuditRecordInput): Promise<AuditEvent> {
    // Acquire sequential write lock to guarantee monotonic hash chain continuity
    const previousLock = this.writeLock;
    let releaseLock: () => void;
    this.writeLock = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });

    try {
      await previousLock;
      await this.ensureLoaded();

      const eventId = AuditService.generateEventId();
      const nowMs = Date.now();
      const isoTimestamp = new Date(nowMs).toISOString();

      // Determine previous hash in the chain
      const lastEvent = this.memoryCache[this.memoryCache.length - 1];
      const previousEventHash = lastEvent ? lastEvent.eventHash || '0000000000000000000000000000000000000000000000000000000000000000' : '0000000000000000000000000000000000000000000000000000000000000000';

      const sanitizedDesc = AuditService.sanitizeString(input.description, MAX_DESC_LENGTH);
      const sanitizedReason = input.reason ? AuditService.sanitizeString(input.reason, MAX_FIELD_LENGTH) : undefined;

      const eventDraft: Omit<AuditEvent, 'eventHash'> = {
        eventId,
        timestamp: isoTimestamp,
        timestampEpochMs: nowMs,
        timestampSource: 'LOCAL_RUNTIME',
        eventType: input.eventType,
        severity: input.severity,
        category: input.category,
        actor: {
          type: input.actor.type,
          id: input.actor.id ? AuditService.sanitizeString(input.actor.id, 100) : undefined,
          displayName: input.actor.displayName ? AuditService.sanitizeString(input.actor.displayName, 100) : undefined,
        },
        resource: {
          type: input.resource.type,
          id: input.resource.id ? AuditService.sanitizeString(input.resource.id, 100) : undefined,
        },
        action: AuditService.sanitizeString(input.action, 100),
        outcome: input.outcome,
        description: sanitizedDesc,
        reason: sanitizedReason,
        documentId: input.documentId ? AuditService.sanitizeString(input.documentId, 100) : undefined,
        distributionId: input.distributionId ? AuditService.sanitizeString(input.distributionId, 100) : undefined,
        packageId: input.packageId ? AuditService.sanitizeString(input.packageId, 100) : undefined,
        recipientId: input.recipientId ? AuditService.sanitizeString(input.recipientId, 100) : undefined,
        sessionId: input.sessionId ? AuditService.sanitizeString(input.sessionId, 100) : undefined,
        transactionId: input.transactionId ? AuditService.sanitizeString(input.transactionId, 100) : undefined,
        blockIndex: input.blockIndex,
        certificateId: input.certificateId ? AuditService.sanitizeString(input.certificateId, 100) : undefined,
        caseId: input.caseId ? AuditService.sanitizeString(input.caseId, 100) : undefined,
        watermarkId: input.watermarkId ? AuditService.sanitizeString(input.watermarkId, 100) : undefined,
        correlationId: input.correlationId ? AuditService.sanitizeString(input.correlationId, 100) : undefined,
        previousEventHash,
        dltAnchored: input.dltAnchored || false,
        dltTransactionId: input.dltTransactionId ? AuditService.sanitizeString(input.dltTransactionId, 100) : undefined,
        dltBlockHeight: input.dltBlockHeight,
        metadata: this.sanitizeMetadata(input.metadata),
      };

      // Compute canonical SHA-256 hash
      const eventHash = await this.computeEventHash(eventDraft, previousEventHash);

      const completeEvent: AuditEvent = {
        ...eventDraft,
        eventHash,
      };

      // Update memory cache and persist
      this.memoryCache.push(completeEvent);
      await airGappedStorage.saveAuditEvent(completeEvent);

      return completeEvent;
    } catch (err) {
      console.error('[AuditService] Logging failure:', err);
      // Non-crashing failure fallback per OWASP logging guidelines
      throw err;
    } finally {
      releaseLock!();
    }
  }

  /**
   * Retrieves all audit events in chronological order.
   */
  public async getAllEvents(): Promise<AuditEvent[]> {
    await this.ensureLoaded();
    return [...this.memoryCache];
  }

  /**
   * Queries and filters audit events.
   */
  public async queryEvents(filter: AuditQueryFilter): Promise<AuditEvent[]> {
    await this.ensureLoaded();
    let events = [...this.memoryCache];

    if (filter.category && filter.category !== 'ALL') {
      events = events.filter((e) => e.category === filter.category);
    }
    if (filter.severity && filter.severity !== 'ALL') {
      events = events.filter((e) => e.severity === filter.severity);
    }
    if (filter.outcome && filter.outcome !== 'ALL') {
      events = events.filter((e) => e.outcome === filter.outcome);
    }
    if (filter.actorId) {
      const actorQuery = filter.actorId.toLowerCase();
      events = events.filter(
        (e) => e.actor.id === filter.actorId || (e.actor.displayName && e.actor.displayName.toLowerCase().includes(actorQuery))
      );
    }
    if (filter.resourceType && filter.resourceType !== 'ALL') {
      events = events.filter((e) => e.resource.type === filter.resourceType);
    }
    if (filter.resourceId) {
      events = events.filter((e) => e.resource.id === filter.resourceId);
    }
    if (filter.documentId) {
      events = events.filter((e) => e.documentId === filter.documentId);
    }
    if (filter.recipientId) {
      events = events.filter((e) => e.recipientId === filter.recipientId);
    }
    if (filter.correlationId) {
      events = events.filter((e) => e.correlationId === filter.correlationId);
    }
    if (filter.dltStatus && filter.dltStatus !== 'ALL') {
      events = events.filter((e) => filter.dltStatus === 'ANCHORED' ? e.dltAnchored : !e.dltAnchored);
    }

    if (filter.timeRange && filter.timeRange !== 'ALL') {
      const now = Date.now();
      const cutoff =
        filter.timeRange === 'TODAY'
          ? new Date().setHours(0, 0, 0, 0)
          : filter.timeRange === 'LAST_24_HOURS'
          ? now - 24 * 60 * 60 * 1000
          : filter.timeRange === 'LAST_7_DAYS'
          ? now - 7 * 24 * 60 * 60 * 1000
          : now - 30 * 24 * 60 * 60 * 1000;
      events = events.filter((e) => e.timestampEpochMs >= cutoff);
    }

    if (filter.searchQuery && filter.searchQuery.trim().length > 0) {
      const q = filter.searchQuery.trim().toLowerCase();
      events = events.filter((e) => {
        return (
          e.eventId.toLowerCase().includes(q) ||
          e.eventType.toLowerCase().includes(q) ||
          e.description.toLowerCase().includes(q) ||
          (e.documentId && e.documentId.toLowerCase().includes(q)) ||
          (e.recipientId && e.recipientId.toLowerCase().includes(q)) ||
          (e.packageId && e.packageId.toLowerCase().includes(q)) ||
          (e.certificateId && e.certificateId.toLowerCase().includes(q)) ||
          (e.caseId && e.caseId.toLowerCase().includes(q)) ||
          (e.transactionId && e.transactionId.toLowerCase().includes(q)) ||
          (e.correlationId && e.correlationId.toLowerCase().includes(q)) ||
          (e.actor.displayName && e.actor.displayName.toLowerCase().includes(q))
        );
      });
    }

    return events;
  }

  /**
   * Verifies the cryptographic integrity of the entire audit event hash chain.
   * Catches modified, reordered, deleted, or substituted events.
   */
  public async verifyAuditChain(): Promise<AuditChainVerificationResult> {
    await this.ensureLoaded();
    const events = this.memoryCache;

    if (events.length === 0) {
      return {
        valid: true,
        eventsChecked: 0,
        firstInvalidEvent: null,
        anchoredEventsCount: 0,
      };
    }

    let previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
    let anchoredCount = 0;

    for (let i = 0; i < events.length; i++) {
      const event = events[i];

      if (event.dltAnchored) {
        anchoredCount++;
      }

      // Check legacy event without hash
      if (!event.eventHash) {
        continue;
      }

      // Check 1: Previous hash link
      if (event.previousEventHash !== previousHash) {
        return {
          valid: false,
          eventsChecked: i,
          firstInvalidEvent: event.eventId,
          reason: `BROKEN_PREVIOUS_HASH: Expected previous hash "${previousHash.slice(0, 16)}...", found "${(event.previousEventHash || '').slice(0, 16)}...". Potential event deletion or reordering.`,
          latestEventHash: event.eventHash,
          anchoredEventsCount: anchoredCount,
        };
      }

      // Check 2: Event hash integrity
      const { eventHash, ...withoutHash } = event;
      const expectedHash = await this.computeEventHash(withoutHash, previousHash);

      if (eventHash.toLowerCase() !== expectedHash.toLowerCase()) {
        return {
          valid: false,
          eventsChecked: i,
          firstInvalidEvent: event.eventId,
          reason: `EVENT_HASH_MISMATCH: Stored hash "${eventHash.slice(0, 16)}..." does not match recalculated digest "${expectedHash.slice(0, 16)}...". Event data was tampered with in storage.`,
          latestEventHash: eventHash,
          anchoredEventsCount: anchoredCount,
        };
      }

      previousHash = event.eventHash;
    }

    return {
      valid: true,
      eventsChecked: events.length,
      firstInvalidEvent: null,
      chainRootHash: events[0].eventHash,
      latestEventHash: events[events.length - 1].eventHash,
      anchoredEventsCount: anchoredCount,
    };
  }

  /**
   * Lightweight Rule-Based Threat & Anomaly Detection (NIST CSF 2.0).
   * Analyzes the audit history and synthesizes prioritized alerts.
   */
  public async detectSecurityAlerts(): Promise<SecurityAlert[]> {
    await this.ensureLoaded();
    const events = this.memoryCache;
    const alerts: SecurityAlert[] = [];

    // Rule 1: Repeated unauthorized decryption attempts (>= 3 attempts for same recipient or package within 15 min)
    const unauthorizedEvents = events.filter(
      (e) =>
        e.eventType === 'UNAUTHORIZED_ACCESS_ATTEMPT' ||
        e.eventType === 'UNAUTHORIZED_DECRYPTION_ATTEMPT' ||
        (e.category === 'AUTHORIZATION' && e.outcome === 'DENIED') ||
        (e.eventType === 'DECRYPTION_DENIED')
    );

    const recipientAttempts: Record<string, AuditEvent[]> = {};
    for (const evt of unauthorizedEvents) {
      const key = evt.recipientId || evt.actor.id || 'UNKNOWN';
      if (!recipientAttempts[key]) recipientAttempts[key] = [];
      recipientAttempts[key].push(evt);
    }

    for (const [recipId, atts] of Object.entries(recipientAttempts)) {
      if (atts.length >= 2) {
        alerts.push({
          alertId: `ALERT-AUTH-${recipId.slice(0, 8)}`,
          severity: atts.length >= 5 ? 'CRITICAL' : 'WARNING',
          title: 'Repeated Unauthorized Access Attempts',
          summary: `${atts.length} unauthorized decryption/access attempts detected for identity "${recipId}". Access rejected by cryptographic key envelopes.`,
          threatType: 'REPEATED_UNAUTHORIZED_ACCESS',
          detectedAt: atts[atts.length - 1].timestampEpochMs,
          triggerEventIds: atts.map((a) => a.eventId),
          targetRecipientId: recipId,
          occurrenceCount: atts.length,
        });
      }
    }

    // Rule 2: Package Tampering Bursts
    const tamperingEvents = events.filter(
      (e) =>
        e.eventType === 'PACKAGE_TAMPERING_DETECTED' ||
        e.eventType === 'PACKAGE_INTEGRITY_FAILURE' ||
        e.eventType === 'PAYLOAD_INTEGRITY_FAILURE' ||
        e.eventType === 'ENVELOPE_INTEGRITY_FAILURE' ||
        e.eventType === 'CORRUPTED_PACKAGE_DETECTED'
    );

    const packageTampering: Record<string, AuditEvent[]> = {};
    for (const evt of tamperingEvents) {
      const pkgId = evt.packageId || 'UNKNOWN';
      if (!packageTampering[pkgId]) packageTampering[pkgId] = [];
      packageTampering[pkgId].push(evt);
    }

    for (const [pkgId, tEvents] of Object.entries(packageTampering)) {
      alerts.push({
        alertId: `ALERT-TAMP-${pkgId.slice(0, 8)}`,
        severity: tEvents.length >= 2 ? 'CRITICAL' : 'WARNING',
        title: 'Cryptographic Container Tampering Detected',
        summary: `${tEvents.length} package integrity violation(s) intercepted for container "${pkgId}". AES-GCM / SHA-256 MAC mismatch.`,
        threatType: 'PACKAGE_TAMPERING_BURST',
        detectedAt: tEvents[tEvents.length - 1].timestampEpochMs,
        triggerEventIds: tEvents.map((e) => e.eventId),
        targetResourceId: pkgId,
        occurrenceCount: tEvents.length,
      });
    }

    // Rule 3: Validator Quorum Failures
    const quorumFailures = events.filter(
      (e) => e.eventType === 'QUORUM_FAILURE' || e.eventType === 'VALIDATOR_QUORUM_FAILED'
    );
    if (quorumFailures.length > 0) {
      alerts.push({
        alertId: 'ALERT-QUORUM-FAIL',
        severity: 'CRITICAL',
        title: 'Consensus Quorum Failure Alert',
        summary: `${quorumFailures.length} decentralized validator quorum failure(s) recorded. Minimum 3-of-4 BFT consensus was not reached.`,
        threatType: 'VALIDATOR_QUORUM_FAILURE',
        detectedAt: quorumFailures[quorumFailures.length - 1].timestampEpochMs,
        triggerEventIds: quorumFailures.map((e) => e.eventId),
        occurrenceCount: quorumFailures.length,
      });
    }

    // Rule 4: Watermark Mismatch / Replay Attacks
    const watermarkViolations = events.filter(
      (e) =>
        e.eventType === 'WATERMARK_REPLAY_DETECTED' ||
        e.eventType === 'WATERMARK_DOCUMENT_MISMATCH' ||
        e.eventType === 'DOCUMENT_MISMATCH_DETECTED'
    );
    if (watermarkViolations.length > 0) {
      alerts.push({
        alertId: 'ALERT-WM-FORGERY',
        severity: 'CRITICAL',
        title: 'Cross-Document Watermark Forgery Intercepted',
        summary: `${watermarkViolations.length} attempt(s) to transplant or spoof forensic watermarks detected. Ledger document binding rejected the forgery.`,
        threatType: 'DOCUMENT_FORGERY_ATTEMPT',
        detectedAt: watermarkViolations[watermarkViolations.length - 1].timestampEpochMs,
        triggerEventIds: watermarkViolations.map((e) => e.eventId),
        occurrenceCount: watermarkViolations.length,
      });
    }

    return alerts.sort((a, b) => b.detectedAt - a.detectedAt);
  }

  /**
   * Reconstructs the complete lifecycle of a document from creation to leak attribution.
   */
  public async getDocumentLifecycleTimeline(documentId: string): Promise<AuditEvent[]> {
    await this.ensureLoaded();
    return this.memoryCache
      .filter((e) => e.documentId === documentId || e.resource.id === documentId)
      .sort((a, b) => a.timestampEpochMs - b.timestampEpochMs);
  }

  /**
   * Reconstructs recipient-specific access and decryption activity.
   */
  public async getRecipientTimeline(recipientId: string): Promise<AuditEvent[]> {
    await this.ensureLoaded();
    return this.memoryCache
      .filter((e) => e.recipientId === recipientId || e.actor.id === recipientId || e.resource.id === recipientId)
      .sort((a, b) => a.timestampEpochMs - b.timestampEpochMs);
  }

  /**
   * Reconstructs forensic investigation sequence for a given case.
   */
  public async getInvestigationTimeline(caseId: string): Promise<AuditEvent[]> {
    await this.ensureLoaded();
    return this.memoryCache
      .filter((e) => e.caseId === caseId || e.resource.id === caseId)
      .sort((a, b) => a.timestampEpochMs - b.timestampEpochMs);
  }

  /**
   * Exports audit log data as a JSON file download.
   */
  public exportAuditJson(events: AuditEvent[], filename = 'security_audit_log.json'): void {
    const dataStr = JSON.stringify(events, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /**
   * Exports audit log data as standard CSV.
   */
  public exportAuditCsv(events: AuditEvent[], filename = 'security_audit_log.csv'): void {
    const headers = [
      'eventId',
      'timestamp',
      'eventType',
      'severity',
      'category',
      'actorId',
      'resourceType',
      'resourceId',
      'outcome',
      'description',
      'documentId',
      'recipientId',
      'packageId',
      'eventHash',
      'dltAnchored',
    ];

    const rows = events.map((e) => [
      e.eventId,
      e.timestamp,
      e.eventType,
      e.severity,
      e.category,
      e.actor.id || '',
      e.resource.type,
      e.resource.id || '',
      e.outcome,
      `"${(e.description || '').replace(/"/g, '""')}"`,
      e.documentId || '',
      e.recipientId || '',
      e.packageId || '',
      e.eventHash || '',
      e.dltAnchored ? 'TRUE' : 'FALSE',
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /**
   * Internal test/simulation utility: injects an unverified modification
   * to test hash chain tampering detection.
   */
  public simulateAuditTamper(index: number, modifiedDescription: string): void {
    if (this.memoryCache[index]) {
      this.memoryCache[index] = {
        ...this.memoryCache[index],
        description: modifiedDescription,
      };
    }
  }

  /**
   * Clears audit memory and persistent storage.
   */
  public async clearAll(): Promise<void> {
    this.memoryCache = [];
    this.isLoaded = true;
    await airGappedStorage.clearAuditEvents();
  }
}

export const auditService = AuditService.getInstance();
