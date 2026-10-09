import './setup';
import { test, describe, before, beforeEach } from 'node:test';
import assert from 'node:assert';
import { securityIncidentEngine } from '../src/services/incidentEngine';
import { auditService } from '../src/services/auditService';
import { airGappedStorage } from '../src/storage/airGappedStorage';
import { airGappedLedger } from '../src/ledger/dlt';
import { Recipient } from '../src/types';

describe('SECURITY INCIDENT ENGINE SUITE (INC-01 to INC-10)', () => {
  let testRecipient: Recipient;

  before(async () => {
    await airGappedLedger.initGenesis();
    testRecipient = {
      id: 'REC-INTRUDER-TEST-01',
      name: 'Rogue Operative',
      role: 'Suspected Insider',
      organization: 'Contested Sector',
      clearanceLevel: 'RESTRICTED',
      avatarInitials: 'RO',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      createdAt: Date.now(),
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: '00'.repeat(1184),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: '00'.repeat(1952),
        keyFingerprint: 'RO-FINGERPRINT-01',
      },
    };
    await airGappedStorage.saveRecipient(testRecipient);
  });

  beforeEach(async () => {
    await securityIncidentEngine.clearAll();
    await auditService.clearAll();
  });

  test('INC-01: Rule RULE-AUTH-01 triggers on threshold boundary (>= 2 denials in 15m)', async () => {
    // 1 failure alone should not trigger incident
    await auditService.record({
      eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      severity: 'WARNING',
      category: 'AUTHORIZATION',
      actor: { type: 'USER', id: testRecipient.id },
      resource: { type: 'PACKAGE', id: 'PKG-01' },
      action: 'DECRYPT_DOCUMENT',
      outcome: 'DENIED',
      description: 'First unauthorized access attempt',
      recipientId: testRecipient.id,
    });

    let incidents = await securityIncidentEngine.evaluateAuditStream();
    assert.strictEqual(incidents.length, 0, 'Single denial must not trigger incident');

    // 2nd failure trips threshold (>= 2)
    await auditService.record({
      eventType: 'UNAUTHORIZED_DECRYPTION_ATTEMPT',
      severity: 'WARNING',
      category: 'SECURITY',
      actor: { type: 'USER', id: testRecipient.id },
      resource: { type: 'PACKAGE', id: 'PKG-01' },
      action: 'DECRYPT_DOCUMENT',
      outcome: 'DENIED',
      description: 'Second unauthorized access attempt',
      recipientId: testRecipient.id,
    });

    incidents = await securityIncidentEngine.evaluateAuditStream();
    assert.strictEqual(incidents.length, 1, 'Two denials must create exactly one incident');
    const inc = incidents[0];
    assert.strictEqual(inc.incidentType, 'REPEATED_UNAUTHORIZED_ACCESS');
    assert.strictEqual(inc.severity, 'HIGH');
    assert.strictEqual(inc.confidence, 'HIGH');
    assert.strictEqual(inc.status, 'OPEN');
    assert.strictEqual(inc.evidenceEventIds.length, 2);
    assert.ok(inc.evidenceDigest && inc.evidenceDigest.length === 64);
  });

  test('INC-02: Deduplication — Additional matching events append to existing OPEN incident', async () => {
    for (let i = 0; i < 2; i++) {
      await auditService.record({
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'WARNING',
        category: 'AUTHORIZATION',
        actor: { type: 'USER', id: testRecipient.id },
        resource: { type: 'PACKAGE', id: 'PKG-01' },
        action: 'DECRYPT_DOCUMENT',
        outcome: 'DENIED',
        description: `Denial ${i + 1}`,
        recipientId: testRecipient.id,
      });
    }

    await securityIncidentEngine.evaluateAuditStream();
    let allIncidents = await securityIncidentEngine.getAllIncidents();
    assert.strictEqual(allIncidents.length, 1);
    const originalId = allIncidents[0].incidentId;

    // 3rd denial arrives
    await auditService.record({
      eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      severity: 'WARNING',
      category: 'AUTHORIZATION',
      actor: { type: 'USER', id: testRecipient.id },
      resource: { type: 'PACKAGE', id: 'PKG-01' },
      action: 'DECRYPT_DOCUMENT',
      outcome: 'DENIED',
      description: 'Denial 3',
      recipientId: testRecipient.id,
    });

    await securityIncidentEngine.evaluateAuditStream();
    allIncidents = await securityIncidentEngine.getAllIncidents();
    assert.strictEqual(allIncidents.length, 1, 'Must not create a duplicate incident for same correlation context');
    assert.strictEqual(allIncidents[0].incidentId, originalId);
    assert.strictEqual(allIncidents[0].evidenceEventIds.length, 3);
  });

  test('INC-03: Rule RULE-PKG-02: Cryptographic container tampering triggers CERTAIN confidence', async () => {
    const pkgId = 'PKG-CORRUPT-TEST-99';
    for (let i = 0; i < 2; i++) {
      await auditService.record({
        eventType: 'PACKAGE_TAMPERING_DETECTED',
        severity: 'HIGH' as any,
        category: 'PACKAGE',
        actor: { type: 'SYSTEM' },
        resource: { type: 'PACKAGE', id: pkgId },
        action: 'VERIFY_PACKAGE',
        outcome: 'REJECTED',
        description: `AES-GCM tag mismatch on container ${pkgId}`,
        packageId: pkgId,
      });
    }

    const incidents = await securityIncidentEngine.evaluateAuditStream();
    const pkgInc = incidents.find((i) => i.affectedPackageId === pkgId);
    assert.ok(pkgInc);
    assert.strictEqual(pkgInc.incidentType, 'PACKAGE_INTEGRITY_TAMPER');
    assert.strictEqual(pkgInc.confidence, 'CERTAIN', 'Mathematical cryptographic MAC failure must have CERTAIN confidence');
  });

  test('INC-04: Rule RULE-WM-03: Zero-tolerance watermark replay attack triggers CRITICAL on 1 event', async () => {
    await auditService.record({
      eventType: 'WATERMARK_DOCUMENT_MISMATCH',
      severity: 'CRITICAL',
      category: 'FORENSICS',
      actor: { type: 'SYSTEM' },
      resource: { type: 'INVESTIGATION', id: 'CASE-01' },
      action: 'EXTRACT_WATERMARK',
      outcome: 'REJECTED',
      description: 'Cross-document watermark transplant detected',
      documentId: 'DOC-TOP-SECRET',
      recipientId: testRecipient.id,
    });

    const incidents = await securityIncidentEngine.evaluateAuditStream();
    const wmInc = incidents.find((i) => i.incidentType === 'WATERMARK_DOCUMENT_FORGERY');
    assert.ok(wmInc, 'Must trigger immediately on single occurrence');
    assert.strictEqual(wmInc.severity, 'CRITICAL');
    assert.strictEqual(wmInc.confidence, 'CERTAIN');
  });

  test('INC-05: Rule RULE-DLT-04: Quorum failure generates DLT_QUORUM_FAILURE incident', async () => {
    await auditService.record({
      eventType: 'QUORUM_FAILURE',
      severity: 'CRITICAL',
      category: 'LEDGER',
      actor: { type: 'VALIDATOR' },
      resource: { type: 'LEDGER', id: 'DLT-01' },
      action: 'COMMIT_BLOCK',
      outcome: 'FAILURE',
      description: 'Failed to acquire 3-of-4 validator signatures for block #4',
    });

    const incidents = await securityIncidentEngine.evaluateAuditStream();
    const qInc = incidents.find((i) => i.incidentType === 'DLT_QUORUM_FAILURE');
    assert.ok(qInc);
    assert.strictEqual(qInc.severity, 'CRITICAL');
  });

  test('INC-06: Rule RULE-AUD-05: Broken audit hash-chain generates AUDIT_CHAIN_INTEGRITY_COMPROMISED', async () => {
    // Record authentic event
    const evt = await auditService.record({
      eventType: 'DOCUMENT_ACCESSED',
      severity: 'INFO',
      category: 'DOCUMENT',
      actor: { type: 'USER', id: 'ANALYST-01' },
      resource: { type: 'DOCUMENT', id: 'DOC-01' },
      action: 'VIEW',
      outcome: 'SUCCESS',
      description: 'Authentic baseline entry',
    });

    // Simulate tampering
    auditService.simulateAuditTamper(0, 'TAMPERED: Altered record');

    const incidents = await securityIncidentEngine.evaluateAuditStream();
    const audInc = incidents.find((i) => i.incidentType === 'AUDIT_CHAIN_INTEGRITY_COMPROMISED');
    assert.ok(audInc, 'Must flag compromised audit chain');
    assert.strictEqual(audInc.confidence, 'CERTAIN');

    // Restore for subsequent tests
    auditService.simulateAuditTamper(0, evt.description);
  });

  test('INC-07: Incident Lifecycle Transitions and Investigator Notes', async () => {
    // Setup incident
    for (let i = 0; i < 2; i++) {
      await auditService.record({
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'WARNING',
        category: 'AUTHORIZATION',
        actor: { type: 'USER', id: testRecipient.id },
        resource: { type: 'PACKAGE', id: 'PKG-01' },
        action: 'DECRYPT',
        outcome: 'DENIED',
        description: `Denial ${i}`,
        recipientId: testRecipient.id,
      });
    }

    const incidents = await securityIncidentEngine.evaluateAuditStream();
    const inc = incidents[0];

    // Transition to ACKNOWLEDGED
    const ack = await securityIncidentEngine.transitionIncidentStatus(inc.incidentId, 'ACKNOWLEDGED', 'AGENT-007');
    assert.strictEqual(ack.status, 'ACKNOWLEDGED');

    // Add note
    await securityIncidentEngine.addNote(inc.incidentId, 'AGENT-007', 'James Bond', 'Investigating terminal logs');
    const withNote = await securityIncidentEngine.getIncidentById(inc.incidentId);
    assert.strictEqual(withNote?.investigatorNotes.length, 1);
    assert.strictEqual(withNote?.investigatorNotes[0].text, 'Investigating terminal logs');

    // Transition to RESOLVED
    const resolved = await securityIncidentEngine.transitionIncidentStatus(
      inc.incidentId,
      'RESOLVED',
      'AGENT-007',
      'Suspicious IP isolated and credentials rotated.'
    );
    assert.strictEqual(resolved.status, 'RESOLVED');
    assert.ok(resolved.resolution);
    assert.strictEqual(resolved.resolution.resolvedBy, 'AGENT-007');
  });

  test('INC-08: False-Positive Transition preserves underlying audit evidence', async () => {
    for (let i = 0; i < 2; i++) {
      await auditService.record({
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'WARNING',
        category: 'AUTHORIZATION',
        actor: { type: 'USER', id: testRecipient.id },
        resource: { type: 'PACKAGE', id: 'PKG-01' },
        action: 'DECRYPT',
        outcome: 'DENIED',
        description: `Denial ${i}`,
        recipientId: testRecipient.id,
      });
    }

    const incidents = await securityIncidentEngine.evaluateAuditStream();
    const inc = incidents[0];

    await securityIncidentEngine.transitionIncidentStatus(
      inc.incidentId,
      'FALSE_POSITIVE',
      'SOC-LEAD',
      'User mistyped passphrase during scheduled drill.'
    );

    const fp = await securityIncidentEngine.getIncidentById(inc.incidentId);
    assert.strictEqual(fp?.status, 'FALSE_POSITIVE');
    assert.strictEqual(fp?.resolution?.resolutionCategory, 'FALSE_POSITIVE_CONFIRMED');

    // Verify underlying audit trail was not erased or modified
    const auditEvents = await auditService.getAllEvents();
    const originalDenials = auditEvents.filter((e) => e.recipientId === testRecipient.id);
    assert.ok(originalDenials.length >= 2, 'Underlying audit logs must remain completely intact');
  });

  test('INC-09: Containment Action — Revoking Recipient updates recipient store and verifies outcome', async () => {
    for (let i = 0; i < 2; i++) {
      await auditService.record({
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'WARNING',
        category: 'AUTHORIZATION',
        actor: { type: 'USER', id: testRecipient.id },
        resource: { type: 'PACKAGE', id: 'PKG-01' },
        action: 'DECRYPT',
        outcome: 'DENIED',
        description: `Denial ${i}`,
        recipientId: testRecipient.id,
      });
    }

    const incidents = await securityIncidentEngine.evaluateAuditStream();
    const inc = incidents[0];

    const action = await securityIncidentEngine.executeContainmentAction(
      inc.incidentId,
      'REVOKE_RECIPIENT',
      'SECURITY-OFFICER',
      'Chief InfoSec'
    );

    assert.strictEqual(action.outcome, 'SUCCESS');
    assert.strictEqual(action.actionType, 'REVOKE_RECIPIENT');

    // Verify stored recipient is now REVOKED
    const storedRecipients = (await airGappedStorage.getRecipients()) || [];
    const updated = storedRecipients.find((r: Recipient) => r.id === testRecipient.id);
    assert.strictEqual(updated?.status, 'REVOKED');
  });

  test('INC-10: Circular Logging Suppression — Generating incident does not create recursive incidents', async () => {
    // Record trigger events
    for (let i = 0; i < 2; i++) {
      await auditService.record({
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'WARNING',
        category: 'AUTHORIZATION',
        actor: { type: 'USER', id: testRecipient.id },
        resource: { type: 'PACKAGE', id: 'PKG-01' },
        action: 'DECRYPT',
        outcome: 'DENIED',
        description: `Denial ${i}`,
        recipientId: testRecipient.id,
      });
    }

    // Pass 1: Creates incident and emits INCIDENT_CREATED
    await securityIncidentEngine.evaluateAuditStream();
    const countAfterPass1 = (await securityIncidentEngine.getAllIncidents()).length;

    // Pass 2: Evaluates stream again containing INCIDENT_CREATED and INCIDENT_ACTION_EXECUTED
    await securityIncidentEngine.evaluateAuditStream();
    const countAfterPass2 = (await securityIncidentEngine.getAllIncidents()).length;

    assert.strictEqual(countAfterPass1, countAfterPass2, 'Must not spawn recursive incidents from incident audit events');
  });
});
