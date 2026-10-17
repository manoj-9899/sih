import './setup';
import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { ReceiptService } from '../src/services/receiptService';
import { AssignmentService } from '../src/services/assignmentService';
import { DistributionService } from '../src/services/distributionService';
import { airGappedStorage } from '../src/storage/airGappedStorage';
import { airGappedLedger } from '../src/ledger/dlt';
import { sessionManager } from '../src/crypto/sessionManager';
import { generateRecipientPqcKeys, bytesToHex, signWithMlDsa65, bytesToBase64 } from '../src/crypto/pqc';
import { createUnifiedEncryptedKeystore, unlockKeystoreRecord } from '../src/crypto/keystore';
import { Recipient, ClassifiedDocument, SignedOfflineReceipt } from '../src/types';

describe('AEGIS-PQC: SIGNED OFFLINE RECEIPTS (.sihrcpt) SECURITY AUDIT SUITE (RCPT-01 to RCPT-14)', () => {
  let doc: ClassifiedDocument;
  let alice: Recipient;
  let bob: Recipient;
  let aliceKeystore: any;
  let bobKeystore: any;
  const alicePassphrase = 'AlicePassword2026!';
  const bobPassphrase = 'BobPassword2026!';

  beforeEach(async () => {
    sessionManager.lockSession();
    await airGappedStorage.clearAll();
    await airGappedLedger.initGenesis();

    const aliceKeys = await generateRecipientPqcKeys();
    const bobKeys = await generateRecipientPqcKeys();

    aliceKeystore = await createUnifiedEncryptedKeystore(
      'REC-ALICE-01',
      aliceKeys.fingerprint,
      aliceKeys.kemSecretKey,
      aliceKeys.dsaSecretKey,
      alicePassphrase
    );

    bobKeystore = await createUnifiedEncryptedKeystore(
      'REC-BOB-01',
      bobKeys.fingerprint,
      bobKeys.kemSecretKey,
      bobKeys.dsaSecretKey,
      bobPassphrase
    );

    await airGappedStorage.saveKeystore(aliceKeystore);
    await airGappedStorage.saveKeystore(bobKeystore);

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
        encryptedKeystore: aliceKeystore,
        keyFingerprint: aliceKeys.fingerprint,
      },
      createdAt: Date.now(),
    };

    bob = {
      id: 'REC-BOB-01',
      name: 'Col. Robert Vance',
      organization: 'Air Defense Command',
      role: 'Operations Commander',
      clearanceLevel: 'SECRET',
      avatarInitials: 'RV',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(bobKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(bobKeys.dsaPublicKey),
        encryptedKeystore: bobKeystore,
        keyFingerprint: bobKeys.fingerprint,
      },
      createdAt: Date.now(),
    };

    airGappedLedger.registerRecipient(alice);
    airGappedLedger.registerRecipient(bob);
    await airGappedStorage.saveRecipient(alice);
    await airGappedStorage.saveRecipient(bob);

    doc = {
      id: 'DOC-CONFIDENTIAL-001',
      title: 'Quantum Defense Grid Blueprint',
      classification: 'TOP SECRET // SCI',
      caveats: 'NOFORN // ORCON',
      originatingOffice: 'Directorate of Aerospace Intelligence',
      summary: 'Quantum radar telemetry parameters',
      rawText: 'CONFIDENTIAL: Quantum radar cross-section telemetry parameters.',
      visualPages: [],
      createdAt: Date.now(),
      isPdf: false,
      mimeType: 'text/plain',
      filename: 'blueprint.txt',
      fileSizeBytes: 64,
    };
  });

  async function loginAlice() {
    const unlocked = await unlockKeystoreRecord(aliceKeystore, alicePassphrase);
    return sessionManager.startSession(alice, unlocked);
  }

  async function loginBob() {
    const unlocked = await unlockKeystoreRecord(bobKeystore, bobPassphrase);
    return sessionManager.startSession(bob, unlocked);
  }

  test('RCPT-01: Generates valid ML-DSA-65 signed receipt and confirms ledger provenance', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice, bob]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const assignments = await AssignmentService.getAssignmentsForRecipient(alice.id, aliceSession);
    const assignment = assignments.find((a) => a.packageId === pkg.packageId);

    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      assignment,
      session: aliceSession,
    });

    assert.equal(receipt.magic, 'SIHRCPT01');
    assert.equal(receipt.version, 1);
    assert.ok(receipt.receiptId.startsWith('RCPT-'));
    assert.equal(receipt.packageId, pkg.packageId);
    assert.equal(receipt.recipientId, alice.id);
    assert.equal(receipt.signatureAlgorithm, 'ML-DSA-65');
    assert.ok(receipt.signatureBase64.length > 100);

    // Verify offline
    const verification = await ReceiptService.verifyReceipt(receipt);
    assert.equal(verification.valid, true);
    assert.equal(verification.signatureValid, true);
    assert.equal(verification.identityBound, true);
    assert.equal(verification.ledgerVerified, true);
    assert.equal(verification.registeredRecipientFound, true);
    assert.equal(verification.provenanceAssurance, 'AUTHENTIC_AND_LEDGER_CONFIRMED');
    assert.equal(verification.errors.length, 0);
  });

  test('RCPT-02: Receipt payload tampering (blockHeight / title / watermark) is rejected', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    // Tamper with block height
    const tamperedReceipt = { ...receipt, blockHeight: 999 };
    const verification1 = await ReceiptService.verifyReceipt(tamperedReceipt);
    assert.equal(verification1.valid, false);
    assert.equal(verification1.signatureValid, false);
    assert.ok(verification1.errors.some((e) => e.includes('signature does not match')));

    // Tamper with document title
    const tamperedTitle = { ...receipt, documentTitle: 'Substituted Classified Title' };
    const verification2 = await ReceiptService.verifyReceipt(tamperedTitle);
    assert.equal(verification2.valid, false);
    assert.equal(verification2.signatureValid, false);
  });

  test('RCPT-03: Signer identifier switching (attribution theft) is rejected', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice, bob]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    // Adversary changes recipientId to Bob to frame Bob
    const tamperedRecipient = { ...receipt, recipientId: bob.id };
    const verification = await ReceiptService.verifyReceipt(tamperedRecipient);
    assert.equal(verification.valid, false);
    assert.equal(verification.signatureValid, false);
    // Verified against Bob's registered key, where Alice's signature fails
    assert.ok(verification.errors.length > 0);
  });

  test('RCPT-04: Public key substitution attack is detected and rejected', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    // Attacker generates their own keypair and substitutes signerPublicKeyHex
    const adversaryKeys = await generateRecipientPqcKeys();
    const substitutedReceipt: SignedOfflineReceipt = {
      ...receipt,
      signerPublicKeyHex: bytesToHex(adversaryKeys.dsaPublicKey),
    };

    const verification = await ReceiptService.verifyReceipt(substitutedReceipt);
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some((e) => e.includes('KeySubstitutionDetected')));
  });

  test('RCPT-05: Untrusted / unregistered signer is strictly rejected', async () => {
    // Adversary creates their own receipt claiming to be "MALLORY-UNKNOWN"
    const adversaryKeys = await generateRecipientPqcKeys();
    const adversaryPayload = {
      magic: 'SIHRCPT01' as const,
      version: 1 as const,
      receiptId: 'RCPT-MALLORY-001',
      packageId: 'PKG-TEST',
      documentId: 'DOC-TEST',
      documentTitle: 'Forged Document',
      classification: 'SECRET',
      recipientId: 'REC-MALLORY-UNREGISTERED',
      recipientName: 'Mallory Adversary',
      recipientFingerprint: adversaryKeys.fingerprint,
      decryptionTimestamp: Date.now(),
      decryptionEventId: 'EVT-MALLORY-01',
      blockHeight: 1,
      blockHash: 'hash-01',
      watermarkId: 'WM-MALLORY',
      watermarkCommitment: 'comm-mallory',
      createdAt: Date.now(),
    };

    const canonicalMsg = ReceiptService.canonicalizeReceipt(adversaryPayload);
    const sig = signWithMlDsa65(new TextEncoder().encode(canonicalMsg), adversaryKeys.dsaSecretKey);

    const forgedReceipt: SignedOfflineReceipt = {
      ...adversaryPayload,
      signatureAlgorithm: 'ML-DSA-65',
      signatureBase64: bytesToBase64(sig),
      signerPublicKeyHex: bytesToHex(adversaryKeys.dsaPublicKey),
    };

    const verification = await ReceiptService.verifyReceipt(forgedReceipt);
    assert.equal(verification.valid, false);
    assert.equal(verification.registeredRecipientFound, false);
    assert.equal(verification.identityBound, false);
    assert.ok(verification.errors.some((e) => e.includes('UntrustedSigner')));
    assert.equal(verification.provenanceAssurance, 'UNTRUSTED_OR_TAMPERED');
  });

  test('RCPT-06: Corrupt or truncated signature bytes are detected and rejected', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    // 1. Bit-flip signature
    const corruptSig = receipt.signatureBase64.slice(0, 10) + 'AAAA' + receipt.signatureBase64.slice(14);
    const tamperedSigReceipt = { ...receipt, signatureBase64: corruptSig };
    const verification1 = await ReceiptService.verifyReceipt(tamperedSigReceipt);
    assert.equal(verification1.valid, false);
    assert.equal(verification1.signatureValid, false);

    // 2. Truncated signature (less than 3309 bytes)
    const truncatedReceipt = { ...receipt, signatureBase64: bytesToBase64(new Uint8Array(64)) };
    const verification2 = await ReceiptService.verifyReceipt(truncatedReceipt);
    assert.equal(verification2.valid, false);
    assert.equal(verification2.signatureValid, false);
  });

  test('RCPT-07: Malformed JSON and unsupported versions are handled gracefully', async () => {
    // 1. Invalid JSON
    const res1 = await ReceiptService.verifyReceipt('not a json string at all');
    assert.equal(res1.valid, false);
    assert.equal(res1.provenanceAssurance, 'INVALID_STRUCTURE');
    assert.ok(res1.errors.some((e) => e.includes('not valid JSON')));

    // 2. Invalid magic header
    const badMagic = JSON.stringify({ magic: 'FAKE_MAGIC', version: 1, receiptId: 'RCPT-1' });
    const res2 = await ReceiptService.verifyReceipt(badMagic);
    assert.equal(res2.valid, false);
    assert.ok(res2.errors.some((e) => e.includes('Unrecognized magic header')));

    // 3. Unsupported version
    const badVersion = JSON.stringify({ magic: 'SIHRCPT01', version: 99, receiptId: 'RCPT-1' });
    const res3 = await ReceiptService.verifyReceipt(badVersion);
    assert.equal(res3.valid, false);
    assert.ok(res3.errors.some((e) => e.includes('UnsupportedReceiptVersion')));
  });

  test('RCPT-08: Canonicalization edge cases: Property reordering and extra nested properties', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    // Reorder properties in serialized JSON
    const reorderedJson = JSON.stringify({
      version: receipt.version,
      magic: receipt.magic,
      signerPublicKeyHex: receipt.signerPublicKeyHex,
      signatureBase64: receipt.signatureBase64,
      signatureAlgorithm: receipt.signatureAlgorithm,
      createdAt: receipt.createdAt,
      watermarkCommitment: receipt.watermarkCommitment,
      watermarkId: receipt.watermarkId,
      blockHash: receipt.blockHash,
      blockHeight: receipt.blockHeight,
      decryptionEventId: receipt.decryptionEventId,
      decryptionTimestamp: receipt.decryptionTimestamp,
      recipientFingerprint: receipt.recipientFingerprint,
      recipientName: receipt.recipientName,
      recipientId: receipt.recipientId,
      classification: receipt.classification,
      documentTitle: receipt.documentTitle,
      documentId: receipt.documentId,
      packageId: receipt.packageId,
      distributionId: receipt.distributionId,
      assignmentId: receipt.assignmentId,
      receiptId: receipt.receiptId,
      clientMetadata: receipt.clientMetadata,
    });

    // Parsing and verifying reordered JSON must succeed because canonicalization normalizes order
    const verification = await ReceiptService.verifyReceipt(reorderedJson);
    assert.equal(verification.valid, true);
    assert.equal(verification.signatureValid, true);
  });

  test('RCPT-09: Ledger corroboration detects unconfirmed or pruned blocks', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    // Create a receipt with a valid signature, but pointing to a block height that does NOT exist
    const nonExistentBlockReceipt = {
      ...receipt,
      blockHeight: 888,
    };
    // Re-sign for the non-existent block to keep signature mathematically valid
    const can = ReceiptService.canonicalizeReceipt(nonExistentBlockReceipt);
    const sig = signWithMlDsa65(new TextEncoder().encode(can), aliceSession.unlockedKeys!.dsaSecretKey);
    nonExistentBlockReceipt.signatureBase64 = bytesToBase64(sig);

    const verification = await ReceiptService.verifyReceipt(nonExistentBlockReceipt);
    // Signature is mathematically valid, but ledger cannot corroborate
    assert.equal(verification.signatureValid, true);
    assert.equal(verification.identityBound, true);
    assert.equal(verification.ledgerVerified, false);
    assert.equal(verification.provenanceAssurance, 'SIGNATURE_VALID_UNCONFIRMED_LEDGER');
    assert.ok(verification.warnings.some((w) => w.includes('LedgerBlockNotFound')));
  });

  test('RCPT-10: Round-trip JSON serialization and parsing preserves authenticity', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    const serialized = ReceiptService.serializeReceipt(receipt);
    assert.equal(typeof serialized, 'string');
    assert.ok(serialized.includes('SIHRCPT01'));

    const parsed = ReceiptService.parseReceipt(serialized);
    assert.equal(parsed.receiptId, receipt.receiptId);
    assert.equal(parsed.signatureBase64, receipt.signatureBase64);

    const verification = await ReceiptService.verifyReceipt(parsed);
    assert.equal(verification.valid, true);
    assert.equal(verification.signatureValid, true);
  });

  test('RCPT-11: Receipt generation enforces authenticated active session', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice, bob]);
    sessionManager.lockSession();

    const dummyEvent = {
      eventId: 'EVT-TEST-01',
      documentId: doc.id,
      documentTitle: doc.title,
      documentHashSha256: 'abc',
      packageHashSha256: 'def',
      recipientId: alice.id,
      recipientName: alice.name,
      recipientPubkeyFingerprint: alice.keys.keyFingerprint,
      sessionId: 'ses-1',
      watermarkId: 'WM-1',
      watermarkCommitment: 'comm-1',
      timestampEpochMs: Date.now(),
      clientMetadata: { terminalId: 'T1', runtimeSecurity: 'S1' },
      signatureAlgorithm: 'ML-DSA-65' as const,
      recipientSignatureBase64: 'abc',
      status: 'COMMITTED' as const,
    };

    const dummyWm = {
      syncHeader: 0xa55a,
      sessionId: 'ses-1',
      watermarkId: 'WM-1',
      recipientId: alice.id,
      recipientFingerprint: alice.keys.keyFingerprint,
      timestamp: Date.now(),
      eccChecksum: 0,
    };

    // Attempting when locked
    await assert.rejects(
      async () => {
        await ReceiptService.generateReceipt({
          pkg,
          recipient: alice,
          decryptionEvent: dummyEvent,
          watermarkPayload: dummyWm,
          blockHeight: 1,
        });
      },
      (err: Error) => err.message.includes('AuthenticationRequired')
    );

    // Attempting when logged in as Bob to sign as Alice
    const bobSession = await loginBob();
    await assert.rejects(
      async () => {
        await ReceiptService.generateReceipt({
          pkg,
          recipient: alice,
          decryptionEvent: dummyEvent,
          watermarkPayload: dummyWm,
          blockHeight: 1,
          session: bobSession,
        });
      },
      (err: Error) => err.message.includes('SessionMismatch')
    );
  });

  test('RCPT-12: Receipt strictly contains NO plaintext document content or private keys', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    const serialized = ReceiptService.serializeReceipt(receipt);

    // Verify plaintext content is not present
    assert.equal(serialized.includes('CONFIDENTIAL: Quantum radar cross-section'), false);
    // Verify ciphertext/CEK is not present
    assert.equal(serialized.includes(pkg.ciphertextBase64), false);
    // Verify secret keys are not present
    assert.equal((receipt as any).dsaSecretKey, undefined);
    assert.equal((receipt as any).kemSecretKey, undefined);
  });

  test('RCPT-13: Key fingerprint mismatch between receipt and registered identity is rejected', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    // Tamper with fingerprint
    const tamperedReceipt = { ...receipt, recipientFingerprint: 'TAMPERED_FPRINT' };
    const verification = await ReceiptService.verifyReceipt(tamperedReceipt);
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some((e) => e.includes('FingerprintMismatch')));
  });

  test('RCPT-14: Ledger block hash mismatch is detected and rejected', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    // Provide a forged block hash for the valid block height
    const forgedHashReceipt = {
      ...receipt,
      blockHash: '0000000000000000000000000000000000000000000000000000000000000000',
    };
    // Re-sign to isolate the ledger check
    const can = ReceiptService.canonicalizeReceipt(forgedHashReceipt);
    const sig = signWithMlDsa65(new TextEncoder().encode(can), aliceSession.unlockedKeys!.dsaSecretKey);
    forgedHashReceipt.signatureBase64 = bytesToBase64(sig);

    const verification = await ReceiptService.verifyReceipt(forgedHashReceipt);
    assert.equal(verification.ledgerVerified, false);
    assert.ok(verification.errors.some((e) => e.includes('LedgerHashMismatch')));
  });
});
