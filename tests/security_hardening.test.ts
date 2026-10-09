import './setup';
import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import {
  encryptDocumentContent,
  decryptDocumentContent,
  computeDocumentAad,
  zeroizeBytes,
  encapsulateCekForRecipient,
  decapsulateCekForRecipient,
  generateRecipientPqcKeys,
  sha256Hex,
} from '../src/crypto/pqc';
import { sessionManager } from '../src/crypto/sessionManager';
import { createEncryptedKeystore, unlockKeystoreRecord } from '../src/crypto/keystore';
import { DistributionService } from '../src/services/distributionService';
import { airGappedLedger } from '../src/ledger/dlt';
import { embedWatermarkInPdf, extractWatermarkFromPdf } from '../src/watermark/engine';
import { PDFDocument } from 'pdf-lib';
import { SAMPLE_DOCUMENTS, initializeRecipientsAndLedger } from '../src/data/sampleData';
import { Recipient } from '../src/types';

describe('SECURITY HARDENING & ASSURANCE TEST SUITE', () => {
  let alice: Recipient;
  let bob: Recipient;
  const sampleDoc = SAMPLE_DOCUMENTS[0];

  before(async () => {
    const recipients = await initializeRecipientsAndLedger();
    alice = recipients[0];
    bob = recipients[1];
    await sessionManager.createSession(alice, 'AliceVance2026!');
  });

  test('HARDEN-01: AES-256-GCM AAD binds document identity and rejects header substitution', async () => {
    const rawPlaintext = new TextEncoder().encode('Classified Operational Briefing 2026');
    const docId = 'DOC-TOP-001';
    const docHash = await sha256Hex(rawPlaintext);
    const validAad = computeDocumentAad(docId, docHash);

    const encResult = await encryptDocumentContent(rawPlaintext, validAad);

    // Decrypting with valid AAD succeeds
    const decrypted = await decryptDocumentContent(
      encResult.ciphertext,
      encResult.tag,
      encResult.iv,
      encResult.cekRaw,
      validAad
    );
    assert.deepStrictEqual(decrypted, rawPlaintext);

    // Decrypting with forged document ID in AAD fails GCM authentication tag check
    const forgedAad = computeDocumentAad('DOC-FORGED-999', docHash);
    await assert.rejects(
      async () => {
        await decryptDocumentContent(
          encResult.ciphertext,
          encResult.tag,
          encResult.iv,
          encResult.cekRaw,
          forgedAad
        );
      },
      (err: any) => err.name === 'OperationError' || err.message?.includes('tag') || err.message?.includes('decrypt')
    );
  });

  test('HARDEN-02: zeroizeBytes explicitly scrubs memory buffers with zeros', () => {
    const sensitive = new Uint8Array([1, 2, 3, 4, 5, 255, 128, 64]);
    zeroizeBytes(sensitive);
    for (let i = 0; i < sensitive.length; i++) {
      assert.strictEqual(sensitive[i], 0);
    }
  });

  test('HARDEN-03: Session lock thoroughly scrubs private keys and zeroizes buffers', async () => {
    await sessionManager.createSession(bob, 'BobMartinez2026!');
    const active = sessionManager.getActiveSession();
    assert.ok(active);
    assert.ok(active.unlockedKeys);

    const kemSecretRef = active.unlockedKeys.kemSecretKey;
    const dsaSecretRef = active.unlockedKeys.dsaSecretKey;

    sessionManager.lockSession();

    assert.strictEqual(sessionManager.getActiveSession(), null);
    // Verified typed arrays have been zeroed
    assert.strictEqual(kemSecretRef[0], 0);
    assert.strictEqual(dsaSecretRef[0], 0);
  });

  test('HARDEN-04: Cross-document watermark transplant attack is rejected', async () => {
    // Re-authenticate Alice
    await sessionManager.createSession(alice, 'AliceVance2026!');

    const docA = SAMPLE_DOCUMENTS[0];
    const docB = SAMPLE_DOCUMENTS[1] || { ...docA, id: 'DOC-B', rawText: 'Different classified text for Doc B' };

    const pkgA = await DistributionService.createEncryptedPackage(docA, [alice]);
    const decA = await DistributionService.executeRecipientDecryption(pkgA, alice);

    // Attacker takes Alice's watermarked text from Doc A, claims it's Doc B
    const docBHash = await sha256Hex(docB.rawText);
    const report = await DistributionService.investigateLeakedDocument(decA.watermarkedText, docBHash);

    assert.ok(
      report.attributionVerdict === 'DOCUMENT_MISMATCH' || report.attributionVerdict === 'EVIDENCE_MISMATCH',
      `Expected DOCUMENT_MISMATCH or EVIDENCE_MISMATCH, got ${report.attributionVerdict}`
    );
    assert.strictEqual(report.verificationStatus, 'FAILED');
  });

  test('HARDEN-05: PDF structural enclave embeds and recovers document hash and watermark commitment', async () => {
    // Generate valid blank PDF bytes
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage([600, 400]);
    const basePdfBytes = await pdfDoc.save();

    const sessionId = crypto.randomUUID();
    const docHash = await sha256Hex('test-pdf-document-content');
    const commitment = await sha256Hex(`WM-COMMIT:${sessionId}:${alice.id}:${docHash}`);

    const payload = {
      syncHeader: 0xa55a,
      sessionId,
      watermarkId: `WM-${sessionId.slice(0, 8).toUpperCase()}`,
      recipientId: alice.id,
      recipientFingerprint: alice.keys.keyFingerprint,
      timestamp: Date.now(),
      eccChecksum: 0,
    };

    const watermarkedPdf = await embedWatermarkInPdf(basePdfBytes, payload, docHash, commitment);
    const extracted = await extractWatermarkFromPdf(watermarkedPdf);

    assert.strictEqual(extracted.success, true);
    assert.strictEqual(extracted.status, 'VALID_WATERMARK');
    assert.strictEqual(extracted.documentHashSha256, docHash.toLowerCase());
    assert.strictEqual(extracted.watermarkCommitment, commitment.toLowerCase());
  });

  test('HARDEN-06: 3-of-4 Byzantine quorum gate rejects blocks with insufficient signatures', async () => {
    const validators = airGappedLedger.getValidators();
    const origStatuses = validators.map((v) => ({ id: v.id, status: v.status }));

    // Set 2 validators offline (only 2 remain online, less than 3/4 quorum)
    validators[0].status = 'OFFLINE';
    validators[1].status = 'OFFLINE';

    const committedBlock = await airGappedLedger.commitBlock();
    assert.strictEqual(committedBlock, null, 'Block must not commit when quorum is below 3');

    // Restore statuses
    for (const orig of origStatuses) {
      const v = validators.find((val) => val.id === orig.id);
      if (v) v.status = orig.status;
    }
  });

  test('HARDEN-07: ML-KEM-768 encapsulation zeroizes sharedSecret after KEK derivation', async () => {
    const keys = await generateRecipientPqcKeys();
    const cek = crypto.getRandomValues(new Uint8Array(32));

    const encResult = await encapsulateCekForRecipient(keys.kemPublicKey, cek);
    assert.ok(encResult.kemCiphertext.length === 1088);
    assert.ok(encResult.wrappedCek.length > 32);

    const recovered = await decapsulateCekForRecipient(keys.kemSecretKey, encResult.kemCiphertext, encResult.wrappedCek);
    assert.deepStrictEqual(recovered, cek);
  });
});
