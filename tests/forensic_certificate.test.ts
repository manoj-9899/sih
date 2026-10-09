import './setup';
import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import { DistributionService } from '../src/services/distributionService';
import {
  ForensicCertificateService,
  ATTRIBUTION_LEGAL_STATEMENT,
  ATTRIBUTION_LEGAL_DISCLAIMER,
  generateSecureId,
} from '../src/services/forensicCertificateService';
import { airGappedLedger } from '../src/ledger/dlt';
import { airGappedStorage } from '../src/storage/airGappedStorage';
import { generateRecipientPqcKeys, computeDocumentAad, bytesToHex } from '../src/crypto/pqc';
import { sessionManager } from '../src/crypto/sessionManager';
import { createMinimalValidPdf } from '../src/crypto/pdfUtils';
import { ClassifiedDocument, Recipient } from '../src/types';

describe('FORENSIC ATTRIBUTION CERTIFICATE SUITE (CERT-01 to CERT-12)', () => {
  let doc: ClassifiedDocument;
  let alice: Recipient;
  let bob: Recipient;
  let verifiedPdf: Uint8Array;
  let sampleCertJson: string;

  before(async () => {
    await airGappedLedger.initGenesis();
    await airGappedStorage.clearForensicCases();
    await airGappedStorage.clearAttributionCertificates();

    // Setup recipients with genuine PQC keys
    const aliceKeys = await generateRecipientPqcKeys();
    const bobKeys = await generateRecipientPqcKeys();

    alice = {
      id: 'REC-ALICE-01',
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
      id: 'REC-BOB-02',
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

    airGappedLedger.registerRecipient(alice);
    airGappedLedger.registerRecipient(bob);

    // Create a classified PDF document
    const rawPdf = createMinimalValidPdf('Project Antigravity Telemetry Report');
    doc = {
      id: 'DOC-CERT-2026-901',
      title: 'Project Antigravity Telemetry Report',
      classification: 'TOP SECRET // SCI',
      caveats: 'NOFORN // ORCON',
      originatingOffice: 'Directorate of Special Projects',
      summary: 'Quantum telemetry field observations and calibration vectors.',
      rawText: 'Confidential flight telemetry from Groom Lake facility. Vector 48.219, -115.820. Trajectory confirmed.',
      visualPages: ['data:image/svg+xml;utf8,<svg></svg>'],
      createdAt: Date.now(),
      isPdf: true,
      mimeType: 'application/pdf',
      filename: 'Antigravity_Telemetry_2026.pdf',
      pdfBytes: rawPdf,
    };

    // Encrypt package for Alice and Bob
    const encryptedPkg = await DistributionService.createEncryptedPackage(doc, [alice, bob]);

    // Alice decrypts and generates forensically watermarked copy
    const sessionAlice = sessionManager.startSession(alice, {
      kemSecretKey: aliceKeys.kemSecretKey,
      dsaSecretKey: aliceKeys.dsaSecretKey,
    });

    const aliceDecryptionResult = await DistributionService.executeRecipientDecryption(
      encryptedPkg,
      alice,
      sessionAlice
    );

    // Use watermarked PDF binary bytes
    verifiedPdf = aliceDecryptionResult.decryptedBytes;
  });

  test('CERT-01: ID Formatting & Cryptographic Entropy', () => {
    const certId = generateSecureId('CERT');
    const caseId = generateSecureId('CASE');

    assert.match(certId, /^CERT-\d{4}-[A-F0-9]{5}-[A-F0-9]+$/, 'Certificate ID must follow CERT-YYYY-XXXXX-XXXX format');
    assert.match(caseId, /^CASE-\d{4}-[A-F0-9]{5}$/, 'Case ID must follow CASE-YYYY-XXXXX format');

    const certId2 = generateSecureId('CERT');
    assert.notStrictEqual(certId, certId2, 'IDs must be uniquely generated with entropy');
  });

  test('CERT-02: Strict Legal/Security Terminology Compliance', () => {
    assert.strictEqual(
      ATTRIBUTION_LEGAL_STATEMENT,
      'The investigated document contains a valid forensic watermark cryptographically bound to the document and associated with the recorded decryption session of the identified recipient.',
      'Must use the exact legally precise conclusion text'
    );
    assert.ok(
      ATTRIBUTION_LEGAL_DISCLAIMER.includes('does not assert or determine the real-world intent'),
      'Must contain explicit evidentiary non-prejudicial caveat'
    );
  });

  test('CERT-03: End-to-End Investigation Produces Verified Attribution Certificate', async () => {
    const report = await DistributionService.investigateLeakedDocument(verifiedPdf);

    assert.strictEqual(report.verificationStatus, 'VERIFIED');
    assert.strictEqual(report.verdict, 'VERIFIED');
    assert.strictEqual(report.confidenceScore, 100);
    assert.ok(report.attributedRecipient, 'Recipient must be attributed');
    assert.strictEqual(report.attributedRecipient?.id, alice.id);

    // Verify Certificate is attached
    assert.ok(report.certificate, 'Certificate must be issued on verified attribution');
    const cert = report.certificate!;

    assert.match(cert.certificateId, /^CERT-/);
    assert.match(cert.caseId, /^CASE-/);
    assert.strictEqual(cert.attributionStatement, ATTRIBUTION_LEGAL_STATEMENT);
    assert.strictEqual(cert.attributionTarget.recipientId, alice.id);
    assert.strictEqual(cert.attributionTarget.name, alice.name);
    assert.strictEqual(cert.cryptographicProof.signatureAlgorithm, 'ML-DSA-65');
    assert.strictEqual(cert.cryptographicProof.signatureVerified, true);
    assert.strictEqual(cert.cryptographicProof.validatorQuorum.quorumSatisfied, true);
    assert.ok(cert.certificateHashSha256.length === 64, 'Must have 64-character SHA-256 hash');

    sampleCertJson = JSON.stringify(cert);
  });

  test('CERT-04: Independent Certificate Verification Passes Genuine Certificate', async () => {
    assert.ok(sampleCertJson, 'Sample certificate JSON must exist');
    const verifyResult = await ForensicCertificateService.verifyCertificate(sampleCertJson);

    assert.strictEqual(verifyResult.valid, true, 'Genuine certificate must verify as 100% valid');
    assert.strictEqual(verifyResult.tamperDetected, false);
    assert.strictEqual(verifyResult.hashMatch, true);
    assert.strictEqual(verifyResult.signatureValid, true);
    assert.strictEqual(verifyResult.ledgerValid, true);
    assert.strictEqual(verifyResult.quorumValid, true);
    assert.strictEqual(verifyResult.documentBindingValid, true);
  });

  test('CERT-05: Tamper Detection — Modifying Recipient Data Fails Canonical Hash', async () => {
    const cert = JSON.parse(sampleCertJson);
    // Adversary modifies recipient name to frame someone else
    cert.attributionTarget.name = 'Agent Bob Stone';

    const verifyResult = await ForensicCertificateService.verifyCertificate(cert);
    assert.strictEqual(verifyResult.valid, false, 'Tampered certificate must be rejected');
    assert.strictEqual(verifyResult.tamperDetected, true);
    assert.strictEqual(verifyResult.hashMatch, false, 'Canonical certificate hash must fail');
    assert.ok(
      verifyResult.tamperReason?.includes('altered') || verifyResult.tamperReason?.includes('mismatch'),
      'Must explain hash mismatch tampering'
    );
  });

  test('CERT-06: Tamper Detection — Modifying Document Hash is Detected', async () => {
    const cert = JSON.parse(sampleCertJson);
    cert.document.sha256Hash = '0000000000000000000000000000000000000000000000000000000000000000';

    const verifyResult = await ForensicCertificateService.verifyCertificate(cert);
    assert.strictEqual(verifyResult.valid, false);
    assert.strictEqual(verifyResult.tamperDetected, true);
  });

  test('CERT-07: Tamper Detection — Signature Forgery with Recipient Swap Fails PQC Gate', async () => {
    const cert = JSON.parse(sampleCertJson);
    // Adversary changes recipient ID and recalculates certificate hash
    cert.attributionTarget.recipientId = bob.id;
    // Recompute hash so hash matches:
    const { certificateHashSha256, ...draft } = cert;
    const { canonicalizeJson, sha256Hex } = await import('../src/crypto/pqc');
    cert.certificateHashSha256 = await sha256Hex(canonicalizeJson(draft));

    // Even if canonical certificate hash matches, the ML-DSA-65 signature was signed with Alice's key, not Bob's!
    const verifyResult = await ForensicCertificateService.verifyCertificate(cert);
    assert.strictEqual(verifyResult.valid, false, 'Signature gate must catch forged recipient swap');
    assert.strictEqual(verifyResult.signatureValid, false);
  });

  test('CERT-08: Tamper Detection — Block Height Modification Fails Ledger Check', async () => {
    const cert = JSON.parse(sampleCertJson);
    cert.cryptographicProof.ledgerBlockHeight = 999999;
    // Recompute hash
    const { certificateHashSha256, ...draft } = cert;
    const { canonicalizeJson, sha256Hex } = await import('../src/crypto/pqc');
    cert.certificateHashSha256 = await sha256Hex(canonicalizeJson(draft));

    const verifyResult = await ForensicCertificateService.verifyCertificate(cert);
    assert.strictEqual(verifyResult.valid, false);
    assert.strictEqual(verifyResult.ledgerValid, false, 'Non-existent ledger block must fail');
  });

  test('CERT-09: Court-Ready PDF Certificate Generation', async () => {
    const cert = JSON.parse(sampleCertJson);
    const pdfBytes = await ForensicCertificateService.generateCertificatePdf(cert);

    assert.ok(pdfBytes instanceof Uint8Array, 'PDF output must be Uint8Array');
    assert.ok(pdfBytes.length > 500, 'PDF size must be substantial');

    // PDF Magic Header check (%PDF-)
    const header = new TextDecoder().decode(pdfBytes.slice(0, 5));
    assert.strictEqual(header, '%PDF-', 'Generated certificate must have valid PDF magic header');
  });

  test('CERT-10: AirGappedStorage Certificate Persistence & Retrieval', async () => {
    const cert = JSON.parse(sampleCertJson);
    await airGappedStorage.saveAttributionCertificate(cert);

    const retrieved = await airGappedStorage.getAttributionCertificate(cert.certificateId);
    assert.ok(retrieved, 'Certificate must be retrievable by ID');
    assert.strictEqual(retrieved.certificateId, cert.certificateId);

    const retrievedByCase = await airGappedStorage.getAttributionCertificate(cert.caseId);
    assert.ok(retrievedByCase, 'Certificate must be retrievable by case ID');
    assert.strictEqual(retrievedByCase.certificateId, cert.certificateId);
  });

  test('CERT-11: Strict Non-Attribution Gate Throws on Unverified Report', async () => {
    const invalidReport: any = {
      reportId: 'REP-INVALID-01',
      analyzedAt: Date.now(),
      watermarkExtracted: false,
      verificationStatus: 'FAILED',
      verdict: 'NO_WATERMARK',
      evidenceChain: [],
    };

    await assert.rejects(
      async () => {
        await ForensicCertificateService.generateCertificate(invalidReport);
      },
      /Required evidence has not passed verification gates/,
      'Cannot generate certificate for unverified report'
    );
  });

  test('CERT-12: Full Attribution Cycle with Multiple Validators & Cross-Document Forgery Gate', async () => {
    // Cross-document forgery test: attempt to investigate Bob's text with wrong suspected doc hash
    const fakeDocHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const reportCross = await DistributionService.investigateLeakedDocument(verifiedPdf, fakeDocHash);

    assert.strictEqual(reportCross.verificationStatus, 'FAILED');
    assert.strictEqual(reportCross.certificate, undefined, 'No certificate issued when cross-document binding fails');
  });
});
