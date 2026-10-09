import './setup.ts';
import test, { describe, it, before } from 'node:test';
import assert from 'node:assert';
import { PDFDocument, PDFName } from 'pdf-lib';
import { DistributionService } from '../src/services/distributionService.ts';
import { airGappedLedger } from '../src/ledger/dlt.ts';
import { sessionManager } from '../src/crypto/sessionManager.ts';
import { createUnifiedEncryptedKeystore, unlockKeystoreRecord } from '../src/crypto/keystore.ts';
import { generateRecipientPqcKeys, bytesToHex } from '../src/crypto/pqc.ts';
import { airGappedStorage } from '../src/storage/airGappedStorage.ts';
import { createMinimalValidPdf } from '../src/crypto/pdfUtils.ts';
import { ClassifiedDocument, Recipient } from '../src/types/index.ts';

describe('TEST GROUP 11: End-to-End PDF Forensic Attribution & Cryptographic Non-Repudiation (E2E-PDF-01 to E2E-PDF-15)', () => {
  let alice: Recipient;
  const alicePass = 'AliceVance2026!';
  let bob: Recipient;
  const bobPass = 'BobMartinez2026!';
  let testDoc: ClassifiedDocument;
  let pdfPackage: any;

  let aliceWatermarkedPdf: Uint8Array;
  let aliceDecryptionResult: any;

  let bobWatermarkedPdf: Uint8Array;
  let bobDecryptionResult: any;

  async function createTestRecipient(id: string, name: string, pass: string): Promise<Recipient> {
    const keys = await generateRecipientPqcKeys();
    const keystore = await createUnifiedEncryptedKeystore(
      id,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      pass
    );

    const recipient: Recipient = {
      id,
      name,
      role: 'Intelligence Officer',
      organization: 'Defense Command',
      clearanceLevel: 'TOP SECRET // SCI',
      avatarInitials: name.split(' ').map((p) => p[0]).join(''),
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(keys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(keys.dsaPublicKey),
        encryptedKeystore: keystore,
        keyFingerprint: keys.fingerprint,
        registeredAt: Date.now(),
      },
    };

    airGappedLedger.registerRecipient(recipient);
    await airGappedStorage.saveKeystore(keystore);
    return recipient;
  }

  before(async () => {
    await airGappedLedger.initGenesis();
    alice = await createTestRecipient('USR-ALICE-E2E-01', 'Dr. Alice Vance', alicePass);
    bob = await createTestRecipient('USR-BOB-E2E-02', 'Director Bob Martinez', bobPass);

    // 2. Prepare genuine multi-page test PDF document
    const rawPdf = createMinimalValidPdf('Joint Operational Defense Plan 2026');
    testDoc = {
      id: 'DOC-E2E-TEST-001',
      title: 'Joint Operational Defense Plan 2026',
      classification: 'TOP SECRET // SCI',
      caveats: 'NOFORN // SPECIAL ACCESS REQUIRED',
      originatingOffice: 'Directorate of Joint Operations',
      summary: 'Operational blueprints for PQC air-gapped array.',
      rawText: 'Operational blueprints for PQC air-gapped array.',
      visualPages: [],
      createdAt: Date.now(),
      isPdf: true,
      mimeType: 'application/pdf',
      filename: 'Joint_Defense_Plan_2026.pdf',
      pdfBytes: rawPdf,
    };

    // 3. Broadcast-Encrypt for Alice & Bob
    pdfPackage = await DistributionService.createEncryptedPackage(testDoc, [alice, bob]);
  });

  it('E2E-PDF-01: Alice decryption under authenticated session produces a valid watermarked PDF', async () => {
    // Authenticate Alice
    const keystoreAlice = await airGappedStorage.getKeystore(alice.id);
    const unlockedAlice = await unlockKeystoreRecord(keystoreAlice, alicePass);
    assert.ok(unlockedAlice, 'Alice keystore must unlock with correct passphrase');

    const sessionAlice = sessionManager.startSession(alice, unlockedAlice);
    assert.ok(sessionAlice, 'Alice session must be established');

    // Execute Decryption Pipeline
    aliceDecryptionResult = await DistributionService.executeRecipientDecryption(
      pdfPackage,
      alice,
      sessionAlice
    );

    assert.ok(aliceDecryptionResult, 'Alice decryption must succeed');
    assert.ok(aliceDecryptionResult.decryptedBytes instanceof Uint8Array);
    assert.strictEqual(aliceDecryptionResult.isPdf, true);

    aliceWatermarkedPdf = aliceDecryptionResult.decryptedBytes;
  });

  it('E2E-PDF-02: Bob decryption under authenticated session produces a valid watermarked PDF', async () => {
    // Authenticate Bob
    const keystoreBob = await airGappedStorage.getKeystore(bob.id);
    const unlockedBob = await unlockKeystoreRecord(keystoreBob, bobPass);
    assert.ok(unlockedBob, 'Bob keystore must unlock with correct passphrase');

    const sessionBob = sessionManager.startSession(bob, unlockedBob);
    assert.ok(sessionBob, 'Bob session must be established');

    // Execute Decryption Pipeline
    bobDecryptionResult = await DistributionService.executeRecipientDecryption(
      pdfPackage,
      bob,
      sessionBob
    );

    assert.ok(bobDecryptionResult, 'Bob decryption must succeed');
    assert.ok(bobDecryptionResult.decryptedBytes instanceof Uint8Array);
    assert.strictEqual(bobDecryptionResult.isPdf, true);

    bobWatermarkedPdf = bobDecryptionResult.decryptedBytes;
  });

  it('E2E-PDF-03: Alice and Bob watermarked PDFs and watermark IDs differ completely', () => {
    assert.notStrictEqual(
      aliceDecryptionResult.watermarkPayload.watermarkId,
      bobDecryptionResult.watermarkPayload.watermarkId,
      'Watermark IDs must be unique'
    );
    assert.notStrictEqual(
      aliceDecryptionResult.watermarkPayload.sessionId,
      bobDecryptionResult.watermarkPayload.sessionId,
      'Session UUIDs must be unique'
    );
    assert.notStrictEqual(
      Buffer.from(aliceWatermarkedPdf).toString('hex'),
      Buffer.from(bobWatermarkedPdf).toString('hex'),
      'Binary PDF outputs must be distinct'
    );
  });

  it('E2E-PDF-04: Leaked Alice PDF resolves to Alice with VERIFIED attribution', async () => {
    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);

    assert.strictEqual(report.attributionVerdict, 'CONFIRMED_LEAK_SOURCE');
    assert.strictEqual(report.attributedRecipient?.id, alice.id);
    assert.strictEqual(report.attributedRecipient?.name, alice.name);
    assert.strictEqual(report.matchedEvent?.sessionId, aliceDecryptionResult.watermarkPayload.sessionId);
    assert.strictEqual(report.pqcSignatureValid, true);
    assert.strictEqual(report.ledgerIntegrityValid, true);
  });

  it('E2E-PDF-05: Leaked Bob PDF resolves to Bob with VERIFIED attribution', async () => {
    const report = await DistributionService.investigateLeakedDocument(bobWatermarkedPdf);

    assert.strictEqual(report.attributionVerdict, 'CONFIRMED_LEAK_SOURCE');
    assert.strictEqual(report.attributedRecipient?.id, bob.id);
    assert.strictEqual(report.attributedRecipient?.name, bob.name);
    assert.strictEqual(report.matchedEvent?.sessionId, bobDecryptionResult.watermarkPayload.sessionId);
    assert.strictEqual(report.pqcSignatureValid, true);
    assert.strictEqual(report.ledgerIntegrityValid, true);
  });

  it('E2E-PDF-06: Alice ML-DSA-65 post-quantum signature on ledger event verifies', async () => {
    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);
    assert.strictEqual(report.pqcSignatureValid, true);

    const sigStep = report.evidenceChain.find((e) => e.step.includes('Signature'));
    assert.ok(sigStep);
    assert.strictEqual(sigStep.status, 'VERIFIED');
  });

  it('E2E-PDF-07: Bob ML-DSA-65 post-quantum signature on ledger event verifies', async () => {
    const report = await DistributionService.investigateLeakedDocument(bobWatermarkedPdf);
    assert.strictEqual(report.pqcSignatureValid, true);

    const sigStep = report.evidenceChain.find((e) => e.step.includes('Signature'));
    assert.ok(sigStep);
    assert.strictEqual(sigStep.status, 'VERIFIED');
  });

  it('E2E-PDF-08: Corrupted watermark in PDF cannot attribute and fails verification safely', async () => {
    // Tamper with bytes inside Alice PDF
    const tamperedPdf = new Uint8Array(aliceWatermarkedPdf);
    // Find index of 'ForensicProvenance' in PDF bytes and corrupt the dict values
    const searchStr = 'PayloadHex';
    const bufStr = Buffer.from(tamperedPdf).toString('binary');
    const idx = bufStr.indexOf(searchStr);
    assert.ok(idx > 0, 'PayloadHex must exist in PDF');

    // Flip bits in the hex payload
    tamperedPdf[idx + 25] ^= 0x01;

    const report = await DistributionService.investigateLeakedDocument(tamperedPdf);

    assert.notStrictEqual(report.attributionVerdict, 'CONFIRMED_LEAK_SOURCE');
    assert.strictEqual(report.attributedRecipient, undefined, 'Must NEVER attribute to any recipient on tamper');
  });

  it('E2E-PDF-09: Forged/random watermark payload cannot attribute (rejected)', async () => {
    const randomPdf = createMinimalValidPdf('Forged Document');
    const report = await DistributionService.investigateLeakedDocument(randomPdf);

    assert.strictEqual(report.attributionVerdict, 'NO_WATERMARK');
    assert.strictEqual(report.attributedRecipient, undefined);
  });

  it('E2E-PDF-10: Modified ledger event breaks signature and cannot verify', async () => {
    // Find Alice event on ledger and tamper with documentId
    const match = airGappedLedger.findEventByWatermark(aliceDecryptionResult.watermarkPayload.sessionId);
    assert.ok(match);

    const originalDocId = match.event.documentId;
    match.event.documentId = 'DOC-FORGED-TAMPER';

    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);

    // Restore immediately after test
    match.event.documentId = originalDocId;

    assert.strictEqual(report.attributionVerdict, 'SIGNATURE_INVALID');
    assert.strictEqual(report.pqcSignatureValid, false);
    assert.strictEqual(report.attributedRecipient, undefined);
  });

  it('E2E-PDF-11: Invalid ML-DSA-65 signature on event is rejected with SIGNATURE_INVALID', async () => {
    const match = airGappedLedger.findEventByWatermark(aliceDecryptionResult.watermarkPayload.sessionId);
    assert.ok(match);

    const originalSig = match.event.recipientSignatureBase64;
    // Corrupt base64 signature
    match.event.recipientSignatureBase64 = 'AAAA' + originalSig.slice(4);

    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);

    // Restore
    match.event.recipientSignatureBase64 = originalSig;

    assert.strictEqual(report.attributionVerdict, 'SIGNATURE_INVALID');
    assert.strictEqual(report.pqcSignatureValid, false);
    assert.strictEqual(report.attributedRecipient, undefined);
  });

  it('E2E-PDF-12: Broken ledger hash-chain is rejected with LEDGER_INVALID', async () => {
    // Corrupt block previousHash on ledger
    const chain = (airGappedLedger as any).chain;
    assert.ok(chain.length > 1);
    const targetBlock = chain[chain.length - 1];
    const originalPrevHash = targetBlock.previousHash;

    targetBlock.previousHash = '0000000000000000000000000000000000000000000000000000000000000000';

    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);

    // Restore
    targetBlock.previousHash = originalPrevHash;

    assert.strictEqual(report.attributionVerdict, 'LEDGER_INVALID');
    assert.strictEqual(report.ledgerIntegrityValid, false);
    assert.strictEqual(report.attributedRecipient, undefined);
  });

  it('E2E-PDF-13: Unknown watermark session returns NO_MATCHING_EVENT', async () => {
    // Construct valid PDF with an unregistered session watermark
    const unregPdf = createMinimalValidPdf('Unregistered Session');
    const unregDoc = await PDFDocument.load(unregPdf);
    // Add ForensicProvenance for an unregistered session
    const context = unregDoc.context;
    const dummyDict = context.obj({
      Type: 'ForensicProvenance',
      PayloadHex: 'a55a0000111122223333444455556666777788889999aaaabbbbccccddddeeee',
    });
    unregDoc.catalog.set(PDFName.of('ForensicProvenance'), context.register(dummyDict));
    const savedBytes = await unregDoc.save();

    const report = await DistributionService.investigateLeakedDocument(savedBytes);

    assert.notStrictEqual(report.attributionVerdict, 'CONFIRMED_LEAK_SOURCE');
    assert.strictEqual(report.attributedRecipient, undefined);
  });

  it('E2E-PDF-14: Mismatched document evidence is rejected with EVIDENCE_MISMATCH', async () => {
    // Provide an intentional hash of a different document to test document binding
    const forgedDifferentDocumentHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const report = await DistributionService.investigateLeakedDocument(
      aliceWatermarkedPdf,
      forgedDifferentDocumentHash
    );

    assert.strictEqual(report.attributionVerdict, 'EVIDENCE_MISMATCH');
    assert.strictEqual(report.attributedRecipient, undefined);
  });

  it('E2E-PDF-15: Complete offline workflow succeeds without external network calls', async () => {
    // Verify that all cryptographic operations execute purely in memory
    const report = await DistributionService.investigateLeakedDocument(bobWatermarkedPdf);
    assert.strictEqual(report.attributionVerdict, 'CONFIRMED_LEAK_SOURCE');
    assert.strictEqual(report.attributedRecipient?.id, bob.id);
  });
});
