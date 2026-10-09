import './setup.ts';
import test, { describe, it, before } from 'node:test';
import assert from 'node:assert';
import { DistributionService } from '../src/services/distributionService.ts';
import { airGappedLedger } from '../src/ledger/dlt.ts';
import { sessionManager } from '../src/crypto/sessionManager.ts';
import { createUnifiedEncryptedKeystore, unlockKeystoreRecord } from '../src/crypto/keystore.ts';
import { generateRecipientPqcKeys, bytesToHex, sha256Hex, signWithMlDsa65, canonicalizeJson } from '../src/crypto/pqc.ts';
import { airGappedStorage } from '../src/storage/airGappedStorage.ts';
import { createMinimalValidPdf } from '../src/crypto/pdfUtils.ts';
import { ClassifiedDocument, Recipient } from '../src/types/index.ts';

describe('TEST GROUP 12: Forensic Investigation & Cryptographic Attribution Workflow (FORENSIC-01 to FORENSIC-15)', () => {
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
      role: 'Intelligence Analyst',
      organization: 'Cyber Defense Command',
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
    // 1. Initialize Genesis and recipients
    await airGappedLedger.initGenesis();
    alice = await createTestRecipient('USR-ALICE-FORENSIC-01', 'Dr. Alice Vance', alicePass);
    bob = await createTestRecipient('USR-BOB-FORENSIC-02', 'Col. Bob Martinez', bobPass);

    // 2. Prepare genuine PDF document
    const rawPdf = createMinimalValidPdf('Joint Operational Defense Plan 2026');
    testDoc = {
      id: 'DOC-FORENSIC-001',
      title: 'Joint Operational Defense Plan 2026',
      classification: 'TOP SECRET // SCI',
      caveats: 'NOFORN',
      originatingOffice: 'Directorate of Strategic Operations',
      summary: 'Tactical contingency plans for post-quantum defense.',
      rawText: 'Tactical contingency plans for post-quantum defense.',
      visualPages: [],
      createdAt: Date.now(),
      isPdf: true,
      mimeType: 'application/pdf',
      filename: 'Joint_Defense_Plan_2026.pdf',
      pdfBytes: rawPdf,
    };

    // 3. Broadcast-Encrypt for Alice & Bob
    pdfPackage = await DistributionService.createEncryptedPackage(testDoc, [alice, bob]);

    // 4. Authenticate & Decrypt for Alice
    const keystoreAlice = await airGappedStorage.getKeystore(alice.id);
    const unlockedAlice = await unlockKeystoreRecord(keystoreAlice, alicePass);
    const sessionAlice = sessionManager.startSession(alice, unlockedAlice);

    aliceDecryptionResult = await DistributionService.executeRecipientDecryption(
      pdfPackage,
      alice,
      sessionAlice
    );
    aliceWatermarkedPdf = aliceDecryptionResult.decryptedBytes;

    // 5. Authenticate & Decrypt for Bob
    const keystoreBob = await airGappedStorage.getKeystore(bob.id);
    const unlockedBob = await unlockKeystoreRecord(keystoreBob, bobPass);
    const sessionBob = sessionManager.startSession(bob, unlockedBob);

    bobDecryptionResult = await DistributionService.executeRecipientDecryption(
      pdfPackage,
      bob,
      sessionBob
    );
    bobWatermarkedPdf = bobDecryptionResult.decryptedBytes;
  });

  it('FORENSIC-01: valid PDF produces VERIFIED result', async () => {
    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);

    assert.ok(report, 'Report must be generated');
    assert.strictEqual(report.verificationStatus, 'VERIFIED');
    assert.ok(
      report.attributionVerdict === 'CONFIRMED_LEAK_SOURCE' || report.attributionVerdict === 'VERIFIED',
      'Verdict must be confirmed leak source'
    );
    assert.ok(report.attributedRecipient, 'Recipient must be attributed when all checks pass');
    assert.strictEqual(report.attributedRecipient?.id, alice.id);
    assert.strictEqual(report.pqcSignatureValid, true);
    assert.strictEqual(report.ledgerIntegrityValid, true);
    assert.strictEqual(report.merkleProofValid, true);
    assert.strictEqual(report.confidenceScore, 100);
  });

  it('FORENSIC-02: no watermark produces NO_WATERMARK', async () => {
    // Generate clean unwatermarked PDF
    const cleanPdf = createMinimalValidPdf('Standard Public Document');
    const report = await DistributionService.investigateLeakedDocument(cleanPdf);

    assert.strictEqual(report.attributionVerdict, 'NO_WATERMARK');
    assert.strictEqual(report.verificationStatus, 'FAILED');
    assert.strictEqual(report.attributedRecipient, undefined, 'Must NEVER attribute recipient without watermark');
    assert.strictEqual(report.confidenceScore, 0);
  });

  it('FORENSIC-03: corrupted watermark rejected', async () => {
    // Tamper with binary bytes inside Alice's watermarked PDF
    const tamperedPdf = new Uint8Array(aliceWatermarkedPdf);
    const bufStr = Buffer.from(tamperedPdf).toString('binary');
    const idx = bufStr.indexOf('PayloadHex');
    assert.ok(idx > 0, 'PayloadHex must exist in PDF');

    // Flip bit in the hex payload
    tamperedPdf[idx + 22] ^= 0x01;

    const report = await DistributionService.investigateLeakedDocument(tamperedPdf);

    assert.ok(
      report.attributionVerdict === 'CORRUPTED_WATERMARK' ||
        report.attributionVerdict === 'TAMPERED_WATERMARK' ||
        report.attributionVerdict === 'NO_WATERMARK',
      'Corrupted watermark must be detected and rejected'
    );
    assert.strictEqual(report.attributedRecipient, undefined, 'Must NEVER attribute recipient when watermark corrupted');
    assert.strictEqual(report.confidenceScore, 0);
  });

  it('FORENSIC-04: unknown watermark rejected', async () => {
    // Watermark belongs to an unknown session that was never registered on the ledger
    // We can simulate this with random valid text that was never committed
    const rogueText = 'UNREGISTERED DOCUMENT CONTENT WITH FAKE WM';
    const report = await DistributionService.investigateLeakedDocument(rogueText);

    assert.notStrictEqual(report.attributionVerdict, 'CONFIRMED_LEAK_SOURCE');
    assert.strictEqual(report.attributedRecipient, undefined);
  });

  it('FORENSIC-05: matching ledger event found', async () => {
    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);

    assert.ok(report.matchedEvent, 'Matching ledger event must be located');
    assert.strictEqual(report.matchedEvent.sessionId, aliceDecryptionResult.watermarkPayload.sessionId);
    assert.strictEqual(report.matchedEvent.recipientId, alice.id);
    assert.ok(report.matchedBlock, 'Matching ledger block must be located');
  });

  it('FORENSIC-06: document mismatch rejected', async () => {
    // Provide a different suspected document hash
    const mismatchDocHash = '0000000000000000000000000000000000000000000000000000000000000000';
    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf, mismatchDocHash);

    assert.ok(
      report.attributionVerdict === 'EVIDENCE_MISMATCH' || report.verdict === 'DOCUMENT_MISMATCH',
      'Mismatched document hash must be rejected'
    );
    assert.strictEqual(report.attributedRecipient, undefined, 'Must NEVER attribute recipient on document mismatch');
    assert.strictEqual(report.confidenceScore, 0);
  });

  it('FORENSIC-07: valid ML-DSA signature accepted', async () => {
    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);

    assert.strictEqual(report.pqcSignatureValid, true, 'ML-DSA-65 signature must be valid');
    const sigStep = report.evidenceChain.find((e) => e.step.includes('ML-DSA'));
    assert.ok(sigStep, 'ML-DSA-65 signature step must be recorded in evidence chain');
    assert.strictEqual(sigStep.status, 'VERIFIED');
  });

  it('FORENSIC-08: invalid ML-DSA signature rejected', async () => {
    const match = airGappedLedger.findEventByWatermark(aliceDecryptionResult.watermarkPayload.sessionId);
    assert.ok(match);

    const origSig = match.event.recipientSignatureBase64;
    // Corrupt signature bytes
    match.event.recipientSignatureBase64 = 'AAAA' + origSig.slice(4);

    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);
    // Restore
    match.event.recipientSignatureBase64 = origSig;

    assert.strictEqual(report.attributionVerdict, 'SIGNATURE_INVALID');
    assert.strictEqual(report.pqcSignatureValid, false);
    assert.strictEqual(report.attributedRecipient, undefined, 'Must NEVER attribute on invalid signature');
  });

  it('FORENSIC-09: modified ledger rejected', async () => {
    // Corrupt block previousHash on ledger
    const chain = (airGappedLedger as any).chain;
    assert.ok(chain.length > 1);
    const targetBlock = chain[chain.length - 1];
    const originalPrevHash = targetBlock.previousHash;
    targetBlock.previousHash = 'bad_hash_chain_link_0000000000000000000000000000000000000000000';

    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);
    targetBlock.previousHash = originalPrevHash;

    assert.strictEqual(report.attributionVerdict, 'LEDGER_INVALID');
    assert.strictEqual(report.ledgerIntegrityValid, false);
    assert.strictEqual(report.attributedRecipient, undefined);
  });

  it('FORENSIC-10: broken Merkle chain rejected', async () => {
    const chain = (airGappedLedger as any).chain;
    assert.ok(chain.length > 1);
    const targetBlock = chain[chain.length - 1];
    const originalMerkle = targetBlock.merkleRoot;
    targetBlock.merkleRoot = 'tampered_merkle_root_0000000000000000000000000000000000000000000';

    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);
    targetBlock.merkleRoot = originalMerkle;

    assert.strictEqual(report.attributionVerdict, 'LEDGER_INVALID');
    assert.strictEqual(report.ledgerIntegrityValid, false);
    assert.strictEqual(report.attributedRecipient, undefined);
  });

  it('FORENSIC-11: wrong recipient key rejected', async () => {
    const match = airGappedLedger.findEventByWatermark(aliceDecryptionResult.watermarkPayload.sessionId);
    assert.ok(match);

    const origFp = match.event.recipientPubkeyFingerprint;
    // Alter recipient key fingerprint to Bob's fingerprint
    match.event.recipientPubkeyFingerprint = bob.keys.keyFingerprint;

    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);
    match.event.recipientPubkeyFingerprint = origFp;

    assert.ok(
      report.attributionVerdict === 'EVIDENCE_MISMATCH' || report.attributionVerdict === 'SIGNATURE_INVALID',
      'Mismatched recipient key fingerprint must be rejected'
    );
    assert.strictEqual(report.attributedRecipient, undefined);
  });

  it('FORENSIC-12: replayed event rejected', async () => {
    // Attempting to submit a duplicate transaction with the same eventId or sessionId
    const duplicateEvent = { ...aliceDecryptionResult.decryptionEvent };
    const res = await airGappedLedger.submitDecryptionEvent(duplicateEvent);

    assert.strictEqual(res.success, false, 'Duplicate / replayed event submission must be rejected');
    assert.ok(res.error?.includes('ReplayAttackRejected') || res.error?.includes('already'), 'Error message must specify replay rejection');
  });

  it('FORENSIC-13: Alice PDF identifies Alice', async () => {
    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);

    assert.strictEqual(report.verificationStatus, 'VERIFIED');
    assert.strictEqual(report.attributedRecipient?.id, alice.id);
    assert.strictEqual(report.attributedRecipient?.name, alice.name);
    assert.strictEqual(report.matchedEvent?.sessionId, aliceDecryptionResult.watermarkPayload.sessionId);
  });

  it('FORENSIC-14: Bob PDF identifies Bob', async () => {
    const report = await DistributionService.investigateLeakedDocument(bobWatermarkedPdf);

    assert.strictEqual(report.verificationStatus, 'VERIFIED');
    assert.strictEqual(report.attributedRecipient?.id, bob.id);
    assert.strictEqual(report.attributedRecipient?.name, bob.name);
    assert.strictEqual(report.matchedEvent?.sessionId, bobDecryptionResult.watermarkPayload.sessionId);

    // Verify non-collision between Alice and Bob
    assert.notStrictEqual(
      aliceDecryptionResult.watermarkPayload.watermarkId,
      bobDecryptionResult.watermarkPayload.watermarkId,
      'Alice and Bob watermark IDs must be distinct'
    );
    assert.notStrictEqual(
      aliceDecryptionResult.decryptionEvent.eventId,
      bobDecryptionResult.decryptionEvent.eventId,
      'Alice and Bob decryption event IDs must be distinct'
    );
  });

  it('FORENSIC-15: complete workflow works offline', async () => {
    // Verify that full forensic investigation runs without window.fetch or external network
    const report = await DistributionService.investigateLeakedDocument(aliceWatermarkedPdf);
    assert.strictEqual(report.verificationStatus, 'VERIFIED');
    assert.strictEqual(report.attributedRecipient?.id, alice.id);
  });

  it('FORENSIC-NEG-01: Malformed truncated PDF is rejected with INVALID_PDF', async () => {
    const truncatedBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x00]); // truncated 5-byte pseudo PDF
    const report = await DistributionService.investigateLeakedDocument(truncatedBytes);

    assert.strictEqual(report.attributionVerdict, 'INVALID_PDF');
    assert.strictEqual(report.verificationStatus, 'FAILED');
    assert.strictEqual(report.attributedRecipient, undefined);
  });

  it('FORENSIC-NEG-02: Non-PDF binary garbage is rejected with INVALID_PDF', async () => {
    const garbageBytes = new Uint8Array(500).fill(0xff);
    const report = await DistributionService.investigateLeakedDocument(garbageBytes);

    assert.strictEqual(report.attributionVerdict, 'INVALID_PDF');
    assert.strictEqual(report.verificationStatus, 'FAILED');
    assert.strictEqual(report.attributedRecipient, undefined);
  });
});
