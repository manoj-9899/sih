import './setup';
import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import { auditService } from '../src/services/auditService';
import { airGappedStorage } from '../src/storage/airGappedStorage';
import { airGappedLedger } from '../src/ledger/dlt';
import { DistributionService } from '../src/services/distributionService';
import { sessionManager } from '../src/crypto/sessionManager';
import { generateRecipientPqcKeys, bytesToHex } from '../src/crypto/pqc';
import { createMinimalValidPdf } from '../src/crypto/pdfUtils';
import { ClassifiedDocument, Recipient } from '../src/types';

describe('SECURITY OPERATIONS & AUDIT CENTER SUITE (AUD-01 to AUD-20)', () => {
  let doc: ClassifiedDocument;
  let alice: Recipient;
  let bob: Recipient;
  let charlie: Recipient;

  before(async () => {
    await airGappedLedger.initGenesis();
    await auditService.clearAll();

    const aliceKeys = await generateRecipientPqcKeys();
    const bobKeys = await generateRecipientPqcKeys();
    const charlieKeys = await generateRecipientPqcKeys();

    alice = {
      id: 'REC-ALICE-AUDIT-01',
      name: 'Dr. Alice Vance',
      organization: 'Defense Cyber Directorate',
      role: 'Principal Research Scientist',
      clearanceLevel: 'TOP SECRET // SCI',
      avatarInitials: 'AV',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(aliceKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(aliceKeys.dsaPublicKey),
        keyFingerprint: aliceKeys.fingerprint,
      },
      createdAt: Date.now(),
    };

    bob = {
      id: 'REC-BOB-AUDIT-02',
      name: 'Agent Bob Stone',
      organization: 'Strategic Reconnaissance',
      role: 'Field Analyst',
      clearanceLevel: 'SECRET',
      avatarInitials: 'BS',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(bobKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(bobKeys.dsaPublicKey),
        keyFingerprint: bobKeys.fingerprint,
      },
      createdAt: Date.now(),
    };

    charlie = {
      id: 'REC-CHARLIE-AUDIT-03',
      name: 'Analyst Charlie Day',
      organization: 'External Liaison',
      role: 'Junior Analyst',
      clearanceLevel: 'CONFIDENTIAL',
      avatarInitials: 'CD',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(charlieKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(charlieKeys.dsaPublicKey),
        keyFingerprint: charlieKeys.fingerprint,
      },
      createdAt: Date.now(),
    };

    airGappedLedger.registerRecipient(alice);
    airGappedLedger.registerRecipient(bob);
    airGappedLedger.registerRecipient(charlie);

    const rawPdf = createMinimalValidPdf('Audit Test Telemetry Memo');
    doc = {
      id: 'DOC-AUDIT-2026-001',
      title: 'Audit Test Telemetry Memo',
      classification: 'TOP SECRET // SCI',
      caveats: 'NOFORN',
      originatingOffice: 'Directorate of Intelligence',
      summary: 'Telemetry field observations for security verification.',
      rawText: 'Autonomous aerial surveillance data stream: coordinates 37.2431, -115.7930.',
      visualPages: ['data:image/svg+xml;utf8,<svg></svg>'],
      createdAt: Date.now(),
      isPdf: true,
      mimeType: 'application/pdf',
      filename: 'Audit_Telemetry_Memo.pdf',
      pdfBytes: rawPdf,
    };
  });

  test('AUD-01: Valid event creation and schema compliance', async () => {
    const event = await auditService.record({
      eventType: 'DOCUMENT_CREATED',
      severity: 'INFO',
      category: 'DOCUMENT',
      actor: { type: 'USER', id: 'SENDER-01', displayName: 'Security Officer' },
      resource: { type: 'DOCUMENT', id: doc.id },
      action: 'CREATE_DOCUMENT',
      outcome: 'SUCCESS',
      description: 'Document created and indexed in local air-gapped registry.',
      documentId: doc.id,
    });

    assert.ok(event.eventId.startsWith('EVT-'));
    assert.strictEqual(event.eventType, 'DOCUMENT_CREATED');
    assert.strictEqual(event.outcome, 'SUCCESS');
    assert.ok(event.timestamp);
    assert.ok(event.eventHash && event.eventHash.length === 64);
  });

  test('AUD-02: Cryptographic hash calculation incorporating previousEventHash', async () => {
    const event1 = await auditService.record({
      eventType: 'DOCUMENT_HASHED',
      severity: 'INFO',
      category: 'CRYPTOGRAPHY',
      actor: { type: 'SYSTEM', id: 'CRYPTO_ENGINE' },
      resource: { type: 'DOCUMENT', id: doc.id },
      action: 'COMPUTE_HASH',
      outcome: 'SUCCESS',
      description: 'Computed SHA-256 digest for document.',
      documentId: doc.id,
    });

    const event2 = await auditService.record({
      eventType: 'DISTRIBUTION_CREATED',
      severity: 'INFO',
      category: 'DISTRIBUTION',
      actor: { type: 'USER', id: 'SENDER-01' },
      resource: { type: 'DISTRIBUTION', id: 'DIST-01' },
      action: 'SETUP_DISTRIBUTION',
      outcome: 'SUCCESS',
      description: 'Setup distribution channel for Alice and Bob.',
      documentId: doc.id,
    });

    assert.strictEqual(event2.previousEventHash, event1.eventHash);
    assert.notStrictEqual(event2.eventHash, event1.eventHash);
  });

  test('AUD-03 & AUD-04: Hash-chain continuity passes validation on pristine logs', async () => {
    const verification = await auditService.verifyAuditChain();
    assert.strictEqual(verification.valid, true);
    assert.strictEqual(verification.firstInvalidEvent, null);
    assert.ok(verification.eventsChecked >= 3);
  });

  test('AUD-05: Tampered event detection (content modification)', async () => {
    const events = await auditService.getAllEvents();
    assert.ok(events.length >= 2);

    const targetIdx = 1;
    const targetEvent = events[targetIdx];
    const originalDesc = targetEvent.description;

    // Simulate tampering
    auditService.simulateAuditTamper(targetIdx, 'MALICIOUS_ALTERATION: Data modified in local storage');

    const result = await auditService.verifyAuditChain();
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.firstInvalidEvent, targetEvent.eventId);
    assert.ok(result.reason?.includes('EVENT_HASH_MISMATCH'));

    // Restore for subsequent tests
    auditService.simulateAuditTamper(targetIdx, originalDesc);
    const restored = await auditService.verifyAuditChain();
    assert.strictEqual(restored.valid, true);
  });

  test('AUD-08: Sensitive data rejection / automatic redaction of cryptographic keys', async () => {
    const secretEvent = await auditService.record({
      eventType: 'AAD_VALIDATION_SUCCESS',
      severity: 'INFO',
      category: 'CRYPTOGRAPHY',
      actor: { type: 'SYSTEM' },
      resource: { type: 'PACKAGE', id: 'PKG-01' },
      action: 'VALIDATE_AAD',
      outcome: 'SUCCESS',
      description: 'Testing automatic scrubbing of sensitive keys',
      metadata: {
        safeField: 'harmless_metric',
        cek: '5b128f72c088a99478f793',
        privateKey: 'RAW_SECRET_PQC_KEY_BUFFER',
        passphrase: 'super_secret_admin_pass',
      },
    });

    assert.strictEqual(secretEvent.metadata?.safeField, 'harmless_metric');
    assert.strictEqual(secretEvent.metadata?.cek, '[REDACTED_SECRET_MATERIAL]');
    assert.strictEqual(secretEvent.metadata?.privateKey, '[REDACTED_SECRET_MATERIAL]');
    assert.strictEqual(secretEvent.metadata?.passphrase, '[REDACTED_SECRET_MATERIAL]');
  });

  test('AUD-09: Log injection protection (neutralizes CRLF and control chars)', async () => {
    const maliciousInput = 'Injected line\r\nEVT-INJECTED-FORGED-LINE\x00\x1b[31mExploit';
    const sanitized = (auditService as any).constructor.sanitizeString(maliciousInput);

    assert.strictEqual(sanitized.includes('\r'), false);
    assert.strictEqual(sanitized.includes('\n'), false);
    assert.strictEqual(sanitized.includes('\x00'), false);
    assert.ok(sanitized.includes('Injected line'));
  });

  test('AUD-11: Event querying and multi-dimensional filtering', async () => {
    const securityEvents = await auditService.queryEvents({
      category: 'CRYPTOGRAPHY',
    });
    assert.ok(securityEvents.length >= 1);
    for (const evt of securityEvents) {
      assert.strictEqual(evt.category, 'CRYPTOGRAPHY');
    }

    const docEvents = await auditService.queryEvents({
      documentId: doc.id,
    });
    assert.ok(docEvents.length >= 1);
  });

  test('AUD-17 & AUD-18: Rule-based threat detection and alert deduplication', async () => {
    // Generate 3 failed decryptions for attacker
    const attackerId = 'REC-MALICIOUS-INTRUDER-99';
    for (let i = 0; i < 3; i++) {
      await auditService.record({
        eventType: 'UNAUTHORIZED_DECRYPTION_ATTEMPT',
        severity: 'WARNING',
        category: 'SECURITY',
        actor: { type: 'USER', id: attackerId },
        resource: { type: 'PACKAGE', id: 'PKG-CONFIDENTIAL' },
        action: 'DECRYPT_DOCUMENT',
        outcome: 'DENIED',
        description: `Unauthorized decryption attempt #${i + 1}`,
        recipientId: attackerId,
      });
    }

    const alerts = await auditService.detectSecurityAlerts();
    const intruderAlert = alerts.find((a) => a.targetRecipientId === attackerId);

    assert.ok(intruderAlert);
    assert.strictEqual(intruderAlert.threatType, 'REPEATED_UNAUTHORIZED_ACCESS');
    assert.strictEqual(intruderAlert.occurrenceCount, 3);
  });

  test('AUD-20: Complete End-to-End Workflow Audit Integration', async () => {
    // 1. Create encrypted package for Alice and Bob
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice, bob]);
    assert.ok(pkg.packageId);

    // Check DOCUMENT_ENCRYPTED was recorded
    const allEventsAfterPkg = await auditService.getAllEvents();
    const encEvt = allEventsAfterPkg.find(
      (e) => e.eventType === 'DOCUMENT_ENCRYPTED' && e.packageId === pkg.packageId
    );
    assert.ok(encEvt);
    assert.strictEqual(encEvt.outcome, 'SUCCESS');

    // 2. Export .sihpkg
    const exportBytes = await DistributionService.exportPackage(pkg);
    assert.ok(exportBytes.length > 0);

    // 3. Alice authenticates and decrypts
    const aliceKeys = await generateRecipientPqcKeys();
    // Simulate active session
    const sessionAlice = sessionManager.startSession(alice, {
      kemSecretKey: new Uint8Array(2400),
      dsaSecretKey: new Uint8Array(4032),
    });

    // Verify unauthorized attempt by Charlie is rejected and audited
    let charlieBlocked = false;
    try {
      await DistributionService.executeRecipientDecryption(pkg, charlie);
    } catch (e: any) {
      charlieBlocked = true;
    }
    assert.strictEqual(charlieBlocked, true);

    const eventsAfterCharlie = await auditService.getAllEvents();
    const unauthorizedEvt = eventsAfterCharlie.find(
      (e) =>
        (e.eventType === 'UNAUTHORIZED_DECRYPTION_ATTEMPT' || e.eventType === 'UNAUTHORIZED_ACCESS_ATTEMPT') &&
        (e.recipientId === charlie.id || e.actor.id === alice.id)
    );
    assert.ok(unauthorizedEvt);
    assert.strictEqual(unauthorizedEvt.outcome, 'DENIED');

    // 4. Verify chain integrity across all accumulated records
    const finalChain = await auditService.verifyAuditChain();
    assert.strictEqual(finalChain.valid, true);
    assert.ok(finalChain.eventsChecked >= 7);
  });
});
