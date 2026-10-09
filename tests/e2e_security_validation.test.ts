import './setup';
import { test, describe, before, beforeEach } from 'node:test';
import assert from 'node:assert';
import { DistributionService } from '../src/services/distributionService';
import { PackageExportService } from '../src/services/packageExportService';
import { sessionManager } from '../src/crypto/sessionManager';
import { auditService } from '../src/services/auditService';
import { securityIncidentEngine } from '../src/services/incidentEngine';
import { ForensicDossierService } from '../src/services/forensicDossierService';
import { airGappedStorage } from '../src/storage/airGappedStorage';
import { airGappedLedger } from '../src/ledger/dlt';
import { ForensicCertificateService } from '../src/services/forensicCertificateService';
import { generateRecipientPqcKeys, bytesToHex, canonicalizeJson, sha256Hex } from '../src/crypto/pqc';
import { ClassifiedDocument, Recipient, EncryptedPackage } from '../src/types';

describe('END-TO-END SECURITY VALIDATION & RELEASE READINESS SUITE (E2E-01 to E2E-08)', () => {
  let docA: ClassifiedDocument;
  let docB: ClassifiedDocument;
  let alice: Recipient;
  let bob: Recipient;
  let eve: Recipient;
  let aliceKeys: any;
  let bobKeys: any;
  let eveKeys: any;

  before(async () => {
    await airGappedLedger.initGenesis();

    aliceKeys = await generateRecipientPqcKeys();
    bobKeys = await generateRecipientPqcKeys();
    eveKeys = await generateRecipientPqcKeys();

    alice = {
      id: 'REC-ALICE-E2E-01',
      name: 'Dr. Alice Vance',
      role: 'Principal Cryptographer',
      organization: 'Defense Cyber Command',
      clearanceLevel: 'TOP SECRET // SCI',
      avatarInitials: 'AV',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      createdAt: Date.now(),
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(aliceKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(aliceKeys.dsaPublicKey),
        keyFingerprint: aliceKeys.fingerprint,
      },
    };

    bob = {
      id: 'REC-BOB-E2E-02',
      name: 'Agent Bob Stone',
      role: 'Intelligence Analyst',
      organization: 'Strategic Defense',
      clearanceLevel: 'SECRET',
      avatarInitials: 'BS',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      createdAt: Date.now(),
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(bobKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(bobKeys.dsaPublicKey),
        keyFingerprint: bobKeys.fingerprint,
      },
    };

    eve = {
      id: 'REC-EVE-E2E-03',
      name: 'Eve Unauthorized',
      role: 'Untrusted Agent',
      organization: 'External Observer',
      clearanceLevel: 'RESTRICTED',
      avatarInitials: 'EU',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      createdAt: Date.now(),
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(eveKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(eveKeys.dsaPublicKey),
        keyFingerprint: eveKeys.fingerprint,
      },
    };

    await airGappedStorage.saveRecipient(alice);
    await airGappedStorage.saveRecipient(bob);
    await airGappedStorage.saveRecipient(eve);

    docA = {
      id: 'DOC-ALPHA-2026',
      title: 'Project Antigravity Telemetry',
      classification: 'TOP SECRET // SCI',
      caveats: 'NOFORN',
      originatingOffice: 'Defense Advanced Research Projects',
      summary: 'Quantum electrodynamics telemetry',
      rawText: 'CONFIDENTIAL: Quantum electrodynamics telemetry indicates stable field harmonics at 4.2 GHz.',
      visualPages: ['data:image/svg+xml;utf8,<svg></svg>'],
      createdAt: Date.now(),
    };

    docB = {
      id: 'DOC-BRAVO-2026',
      title: 'Unclassified Routine Administrative Memo',
      classification: 'CONFIDENTIAL',
      caveats: 'ORCON',
      originatingOffice: 'Operations Base Alpha',
      summary: 'Cafeteria memo',
      rawText: 'ROUTINE: Department cafeteria scheduled maintenance will occur on Thursday afternoon.',
      visualPages: ['data:image/svg+xml;utf8,<svg></svg>'],
      createdAt: Date.now(),
    };
  });

  beforeEach(async () => {
    // Generate fresh authentic keys for each test run to avoid zeroized buffers from prior session locks
    aliceKeys = await generateRecipientPqcKeys();
    bobKeys = await generateRecipientPqcKeys();
    eveKeys = await generateRecipientPqcKeys();

    alice.keys = {
      kemAlgorithm: 'ML-KEM-768',
      kemPublicKeyHex: bytesToHex(aliceKeys.kemPublicKey),
      dsaAlgorithm: 'ML-DSA-65',
      dsaPublicKeyHex: bytesToHex(aliceKeys.dsaPublicKey),
      keyFingerprint: aliceKeys.fingerprint,
    };
    alice.status = 'AUTHORIZED';
    alice.distributionStatus = 'AUTHORIZED';

    bob.keys = {
      kemAlgorithm: 'ML-KEM-768',
      kemPublicKeyHex: bytesToHex(bobKeys.kemPublicKey),
      dsaAlgorithm: 'ML-DSA-65',
      dsaPublicKeyHex: bytesToHex(bobKeys.dsaPublicKey),
      keyFingerprint: bobKeys.fingerprint,
    };
    bob.status = 'AUTHORIZED';
    bob.distributionStatus = 'AUTHORIZED';

    eve.keys = {
      kemAlgorithm: 'ML-KEM-768',
      kemPublicKeyHex: bytesToHex(eveKeys.kemPublicKey),
      dsaAlgorithm: 'ML-DSA-65',
      dsaPublicKeyHex: bytesToHex(eveKeys.dsaPublicKey),
      keyFingerprint: eveKeys.fingerprint,
    };

    await airGappedLedger.reset();

    airGappedLedger.registerRecipient(alice);
    airGappedLedger.registerRecipient(bob);
    airGappedLedger.registerRecipient(eve);

    await airGappedStorage.saveRecipient(alice);
    await airGappedStorage.saveRecipient(bob);
    await airGappedStorage.saveRecipient(eve);

    await securityIncidentEngine.clearAll();
    await auditService.clearAll();
    await airGappedStorage.clearPackages();
    await airGappedStorage.clearForensicDossiers();
  });

  test('E2E-01: Legitimate Lifecycle — Authorized distribution, export, import, decryption, and watermark attribution succeeds', async () => {
    // 1. Encrypt package for Alice and Bob
    const pkg = await DistributionService.createEncryptedPackage(docA, [alice, bob]);
    assert.strictEqual(pkg.envelopes.length, 2);

    // 2. Export to .sihpkg binary format
    const binaryBytes = await PackageExportService.exportPackageToBinary(pkg);
    assert.ok(binaryBytes.length > 0);

    // 3. Alice authenticates into local session
    const aliceSession = sessionManager.startSession(alice, {
      kemSecretKey: aliceKeys.kemSecretKey,
      dsaSecretKey: aliceKeys.dsaSecretKey,
    });

    // 4. Validate & import .sihpkg
    const validation = await PackageExportService.validateAndImportPackage(binaryBytes, alice.id, aliceSession);
    assert.strictEqual(validation.isValid, true);
    assert.strictEqual(validation.recipientAuthorization?.canDecrypt, true);

    // 5. Decrypt document
    const result = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    assert.ok(result.watermarkedText.includes('Quantum electrodynamics telemetry'));
    assert.strictEqual(result.decryptionEvent.recipientId, alice.id);

    // 6. Forensic investigation of watermarked text succeeds
    const investigation = await DistributionService.investigateLeakedDocument(result.watermarkedText);
    assert.strictEqual(investigation.verdict, 'VERIFIED');
    assert.strictEqual(investigation.attributedRecipient?.id, alice.id);
    assert.strictEqual(investigation.pqcSignatureValid, true);
    assert.strictEqual(investigation.merkleProofValid, true);
    assert.ok(investigation.certificate);
  });

  test('E2E-02: Direct Decryption Revocation Bypass Prevention — Revoked envelope is rejected', async () => {
    // Encrypt package for Alice and Bob
    const pkg = await DistributionService.createEncryptedPackage(docA, [alice, bob]);

    // Explicitly revoke Bob's envelope inside the package
    const bobEnvelope = pkg.envelopes.find((e) => e.recipientId === bob.id);
    assert.ok(bobEnvelope);
    bobEnvelope.status = 'REVOKED';

    const bobSession = sessionManager.startSession(bob, {
      kemSecretKey: bobKeys.kemSecretKey,
      dsaSecretKey: bobKeys.dsaSecretKey,
    });

    // Direct invocation of executeRecipientDecryption without .sihpkg import
    let threw = false;
    try {
      await DistributionService.executeRecipientDecryption(pkg, bob, bobSession);
    } catch (err: any) {
      threw = true;
      assert.ok(err.message.includes('revoked'));
    }
    assert.strictEqual(threw, true, 'Direct decryption must be rejected when envelope is REVOKED');

    // Verify audit record emitted
    const events = await auditService.getAllEvents();
    const revokedEvt = events.find((e) => e.eventType === 'REVOKED_DECRYPTION_ATTEMPT');
    assert.ok(revokedEvt, 'Must record REVOKED_DECRYPTION_ATTEMPT in audit log');
  });

  test('E2E-03: Direct Decryption Revocation Prevention — Persisted recipient revocation is enforced', async () => {
    // Encrypt package while Bob was authorized
    const pkg = await DistributionService.createEncryptedPackage(docA, [alice, bob]);

    // Admin revokes Bob in persistent storage (e.g. credential compromise)
    bob.status = 'REVOKED';
    bob.distributionStatus = 'REVOKED';
    await airGappedStorage.saveRecipient(bob);

    const bobSession = sessionManager.startSession(bob, {
      kemSecretKey: bobKeys.kemSecretKey,
      dsaSecretKey: bobKeys.dsaSecretKey,
    });

    let threw = false;
    try {
      await DistributionService.executeRecipientDecryption(pkg, bob, bobSession);
    } catch (err: any) {
      threw = true;
      assert.ok(err.message.includes('REVOKED'));
    }
    assert.strictEqual(threw, true, 'Direct decryption must be rejected when recipient is REVOKED in storage');

    const events = await auditService.getAllEvents();
    const revokedEvt = events.find((e) => e.eventType === 'REVOKED_DECRYPTION_ATTEMPT');
    assert.ok(revokedEvt);
  });

  test('E2E-04: Package Isolation Enforcement — Quarantined package cannot be decrypted', async () => {
    const pkg = await DistributionService.createEncryptedPackage(docA, [alice]);
    await airGappedStorage.savePackage(pkg);

    // Trip incident and execute FLAG_PACKAGE_ISOLATED
    await auditService.record({
      eventType: 'PACKAGE_TAMPERING_DETECTED',
      severity: 'CRITICAL',
      category: 'PACKAGE',
      actor: { type: 'SYSTEM' },
      resource: { type: 'PACKAGE', id: pkg.packageId },
      action: 'AUDIT',
      outcome: 'REJECTED',
      description: 'Container tampering detected',
      packageId: pkg.packageId,
    });
    await auditService.record({
      eventType: 'PACKAGE_TAMPERING_DETECTED',
      severity: 'CRITICAL',
      category: 'PACKAGE',
      actor: { type: 'SYSTEM' },
      resource: { type: 'PACKAGE', id: pkg.packageId },
      action: 'AUDIT',
      outcome: 'REJECTED',
      description: 'Second container tampering failure',
      packageId: pkg.packageId,
    });

    const incidents = await securityIncidentEngine.evaluateAuditStream();
    const targetInc = incidents.find((i) => i.affectedPackageId === pkg.packageId);
    assert.ok(targetInc);

    // Containment action: isolate package
    const action = await securityIncidentEngine.executeContainmentAction(
      targetInc.incidentId,
      'FLAG_PACKAGE_ISOLATED',
      'CHIEF-SEC',
      'InfoSec Lead'
    );
    assert.strictEqual(action.outcome, 'SUCCESS');

    // Attempt decryption by Alice (who has valid keys)
    const aliceSession = sessionManager.startSession(alice, {
      kemSecretKey: aliceKeys.kemSecretKey,
      dsaSecretKey: aliceKeys.dsaSecretKey,
    });

    let threw = false;
    try {
      await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    } catch (err: any) {
      threw = true;
      assert.ok(err.message.includes('PackageQuarantinedError') || err.message.includes('isolated'));
    }
    assert.strictEqual(threw, true, 'Quarantined package must reject decryption');
  });

  test('E2E-05: Cross-Document Watermark Transplant Attack — Detected and triggers CRITICAL incident', async () => {
    // Alice decrypts Doc B (routine cafeteria memo)
    const pkgB = await DistributionService.createEncryptedPackage(docB, [alice]);
    const aliceSession = sessionManager.startSession(alice, {
      kemSecretKey: aliceKeys.kemSecretKey,
      dsaSecretKey: aliceKeys.dsaSecretKey,
    });
    const decB = await DistributionService.executeRecipientDecryption(pkgB, alice, aliceSession);

    // Adversary extracts Alice's zero-width watermark characters from Doc B and appends them to Doc A (Top Secret)
    const zeroWidthChars = decB.watermarkedText.replace(/[^\u200B\u200C\u200D\uFEFF]/g, '');
    const forgedDocument = docA.rawText + zeroWidthChars;

    // Run investigation on forged document
    const investigation = await DistributionService.investigateLeakedDocument(forgedDocument);
    assert.strictEqual(investigation.verdict, 'DOCUMENT_MISMATCH');
    assert.strictEqual(investigation.attributionVerdict, 'DOCUMENT_MISMATCH');

    // Verify incident engine raised CRITICAL incident for watermark transplant
    const incidents = await securityIncidentEngine.evaluateAuditStream();
    const wmInc = incidents.find((i) => i.incidentType === 'WATERMARK_DOCUMENT_FORGERY');
    assert.ok(wmInc, 'Must create incident for watermark transplant attack');
    assert.strictEqual(wmInc.severity, 'CRITICAL');
    assert.strictEqual(wmInc.confidence, 'CERTAIN');
  });

  test('E2E-06: Audit-Chain Tampering — Invalidates live incident and dossier verification', async () => {
    // Generate valid incident
    for (let i = 0; i < 2; i++) {
      await auditService.record({
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'WARNING',
        category: 'AUTHORIZATION',
        actor: { type: 'USER', id: eve.id },
        resource: { type: 'PACKAGE', id: 'PKG-01' },
        action: 'DECRYPT',
        outcome: 'DENIED',
        description: `Denial ${i + 1}`,
        recipientId: eve.id,
      });
    }

    const incidents = await securityIncidentEngine.evaluateAuditStream();
    const inc = incidents[0];
    const dossier = await ForensicDossierService.generateDossier(inc, {
      id: 'INV-01',
      name: 'Agent Fox',
      role: 'Forensic Lead',
    });

    // Verification before tamper is valid
    const preVer = await ForensicDossierService.verifyDossier(dossier);
    assert.strictEqual(preVer.valid, true);

    // Adversary modifies historical audit record
    auditService.simulateAuditTamper(0, 'ALTERED: Tampered audit event payload');

    // Verification after tamper must fail
    const postVer = await ForensicDossierService.verifyDossier(dossier);
    assert.strictEqual(postVer.valid, false);
    assert.strictEqual(postVer.currentLiveVerification.auditChainValid, false);
  });

  test('E2E-07: Forged Evidence References in Dossier — Rejected by independent verification', async () => {
    for (let i = 0; i < 2; i++) {
      await auditService.record({
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'WARNING',
        category: 'AUTHORIZATION',
        actor: { type: 'USER', id: eve.id },
        resource: { type: 'PACKAGE', id: 'PKG-01' },
        action: 'DECRYPT',
        outcome: 'DENIED',
        description: `Denial ${i + 1}`,
        recipientId: eve.id,
      });
    }

    const incidents = await securityIncidentEngine.evaluateAuditStream();
    const dossier = await ForensicDossierService.generateDossier(incidents[0], {
      id: 'INV-01',
      name: 'Agent Fox',
      role: 'Forensic Lead',
    });

    // Attacker modifies an eventId in evidence timeline and re-signs canonical JSON digest
    const forged = JSON.parse(JSON.stringify(dossier));
    forged.evidenceTimeline[0].eventId = 'EVT-NONEXISTENT-PHANTOM-999';
    const { dossierDigestSha256, ...withoutDigest } = forged;
    forged.dossierDigestSha256 = await sha256Hex(canonicalizeJson(withoutDigest));

    const ver = await ForensicDossierService.verifyDossier(forged);
    assert.strictEqual(ver.valid, false);
    assert.strictEqual(ver.tamperDetected, true);
    assert.strictEqual(ver.currentLiveVerification.allEvidenceEventsMatchLiveStore, false);
    assert.ok(ver.currentLiveVerification.missingEventIds.includes('EVT-NONEXISTENT-PHANTOM-999'));
  });

  test('E2E-08: State Persistence Consistency — Air-gapped storage preserves cryptographic linkage after reload', async () => {
    // 1. Create and persist package
    const pkg = await DistributionService.createEncryptedPackage(docA, [alice]);
    await airGappedStorage.savePackage(pkg);

    // 2. Alice decrypts
    const aliceSession = sessionManager.startSession(alice, {
      kemSecretKey: aliceKeys.kemSecretKey,
      dsaSecretKey: aliceKeys.dsaSecretKey,
    });
    const dec = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);

    // 3. Investigate and issue certificate
    const report = await DistributionService.investigateLeakedDocument(dec.watermarkedText);
    assert.ok(report.certificate);
    await airGappedStorage.saveAttributionCertificate(report.certificate);

    // 4. Simulate reload from air-gapped storage
    const reloadedPkg = (await airGappedStorage.getPackages())?.find((p) => p.packageId === pkg.packageId);
    assert.ok(reloadedPkg);
    assert.strictEqual(reloadedPkg.originalDocumentHashSha256, pkg.originalDocumentHashSha256);

    const reloadedCert = await airGappedStorage.getAttributionCertificate(report.certificate.certificateId);
    assert.ok(reloadedCert);
    assert.strictEqual(reloadedCert.certificateId, report.certificate.certificateId);
    assert.strictEqual(reloadedCert.attributionTarget.recipientId, alice.id);

    // 5. Verify certificate passes independent cryptographic audit
    const certVer = await ForensicCertificateService.verifyCertificate(reloadedCert);
    assert.strictEqual(certVer.valid, true);
    assert.strictEqual(certVer.signatureValid, true);
  });
});
