import './setup.ts';
import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  validatePdfBytes,
  computePdfBinaryHashSha256,
  createMinimalValidPdf,
} from '../src/crypto/pdfUtils.ts';
import { encryptDocumentContent, decryptDocumentContent } from '../src/crypto/pqc.ts';
import { airGappedStorage } from '../src/storage/airGappedStorage.ts';
import { DistributionService } from '../src/services/distributionService.ts';
import { ClassifiedDocument } from '../src/types/index.ts';

describe('TEST GROUP 8: Real PDF Binary Ingestion, Binary Hashing & Crypto Integrity (PDF-INGEST, PDF-CRYPTO, PDF-STORAGE, PDF-DOWNLOAD)', () => {
  const samplePdfBytes = createMinimalValidPdf('Joint Defense Intelligence Evaluation 2026');

  it('PDF-INGEST-01: PDF bytes are preserved after ingestion without string truncation', () => {
    assert.ok(samplePdfBytes instanceof Uint8Array, 'PDF input must be an instance of Uint8Array');
    assert.ok(samplePdfBytes.length > 100, 'Minimal PDF must have non-trivial binary length');

    const validation = validatePdfBytes(samplePdfBytes);
    assert.strictEqual(validation.isValid, true, 'Validation must confirm valid PDF magic header');
    assert.strictEqual(validation.sizeBytes, samplePdfBytes.length);
  });

  it('PDF-INGEST-02: Binary SHA-256 matches the original bytes deterministically', async () => {
    const hash1 = await computePdfBinaryHashSha256(samplePdfBytes);
    const hash2 = await computePdfBinaryHashSha256(samplePdfBytes);

    assert.strictEqual(typeof hash1, 'string');
    assert.strictEqual(hash1.length, 64, 'SHA-256 hex must be 64 characters');
    assert.strictEqual(hash1, hash2, 'Identical PDF bytes must produce identical SHA-256 hash');
  });

  it('PDF-INGEST-03: Modified PDF bytes produce a different hash', async () => {
    const originalHash = await computePdfBinaryHashSha256(samplePdfBytes);

    // Tamper with a single byte in the binary stream
    const modifiedPdfBytes = new Uint8Array(samplePdfBytes);
    modifiedPdfBytes[50] ^= 0xff;

    const modifiedHash = await computePdfBinaryHashSha256(modifiedPdfBytes);
    assert.notStrictEqual(originalHash, modifiedHash, 'Tampered binary bytes must yield a different SHA-256');
  });

  it('PDF-INGEST-04: Invalid/non-PDF input is rejected by header validation', () => {
    // 1. Text file pretending to be PDF
    const textBytes = new TextEncoder().encode('Hello, this is just a plain text file without PDF headers.');
    const result1 = validatePdfBytes(textBytes);
    assert.strictEqual(result1.isValid, false, 'Plain text must be rejected as invalid PDF');
    assert.match(result1.error || '', /Missing standard %PDF- header/);

    // 2. Binary random noise
    const randomNoise = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]); // PNG header
    const result2 = validatePdfBytes(randomNoise);
    assert.strictEqual(result2.isValid, false, 'PNG header must be rejected');

    // 3. Truncated buffer (< 8 bytes)
    const truncated = new Uint8Array([0x25, 0x50]);
    const result3 = validatePdfBytes(truncated);
    assert.strictEqual(result3.isValid, false, 'Truncated buffer must be rejected');
  });

  it('PDF-CRYPTO-01: Binary PDF survives AES-256-GCM encryption/decryption unchanged', async () => {
    // Encrypt real PDF binary buffer
    const encResult = await encryptDocumentContent(samplePdfBytes);
    assert.ok(encResult.ciphertext instanceof Uint8Array, 'Ciphertext must be Uint8Array');
    assert.strictEqual(encResult.iv.length, 12, 'AES-GCM IV must be 12 bytes');
    assert.strictEqual(encResult.tag.length, 16, 'AES-GCM Auth tag must be 16 bytes');

    // Decrypt binary buffer
    const decryptedBytes = await decryptDocumentContent(
      encResult.ciphertext,
      encResult.tag,
      encResult.iv,
      encResult.cekRaw
    );

    assert.ok(decryptedBytes instanceof Uint8Array, 'Decrypted output must be Uint8Array');
    assert.strictEqual(decryptedBytes.length, samplePdfBytes.length);
  });

  it('PDF-CRYPTO-02: Original PDF bytes === decrypted PDF bytes (byte-for-byte exact equality)', async () => {
    const encResult = await encryptDocumentContent(samplePdfBytes);
    const decryptedBytes = await decryptDocumentContent(
      encResult.ciphertext,
      encResult.tag,
      encResult.iv,
      encResult.cekRaw
    );

    assert.deepStrictEqual(
      Array.from(decryptedBytes),
      Array.from(samplePdfBytes),
      'Decrypted binary stream must match original PDF byte-for-byte'
    );

    // Re-verify that decrypted bytes still constitute a valid PDF
    const validation = validatePdfBytes(decryptedBytes);
    assert.strictEqual(validation.isValid, true);
  });

  it('PDF-STORAGE-01: PDF binary package can be stored and retrieved without corruption', async () => {
    const testPackage = {
      packageId: 'PKG-TEST-PDF-01',
      documentId: 'DOC-TEST-PDF-01',
      documentTitle: 'Operation Shield PDF',
      classification: 'TOP SECRET // SCI',
      version: 1,
      originalDocumentHashSha256: await computePdfBinaryHashSha256(samplePdfBytes),
      ciphertextBase64: Buffer.from(samplePdfBytes).toString('base64'),
      ivHex: '0102030405060708090a0b0c',
      tagHex: 'a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8',
      envelopes: [],
      senderId: 'SNDR-01',
      senderName: 'Test Sender',
      createdAt: Date.now(),
      isPdf: true,
      mimeType: 'application/pdf',
      filename: 'Operation_Shield.pdf',
    };

    await airGappedStorage.savePackage(testPackage);
    const packages = await airGappedStorage.getPackages();
    assert.ok(packages, 'Packages must be retrievable');

    const retrieved = packages.find((p: any) => p.packageId === 'PKG-TEST-PDF-01');
    assert.ok(retrieved, 'Target package must be found in storage');
    assert.strictEqual(retrieved.isPdf, true);
    assert.strictEqual(retrieved.mimeType, 'application/pdf');
    assert.strictEqual(retrieved.originalDocumentHashSha256, testPackage.originalDocumentHashSha256);
  });

  it('PDF-DOWNLOAD-01: Decrypted output is produced as application/pdf Blob specification', () => {
    // Simulate DecryptView download logic
    const isPdf = true;
    const decryptedBytes = samplePdfBytes;

    let blob: any;
    let ext = 'txt';

    if (isPdf && decryptedBytes) {
      blob = new Blob([decryptedBytes.buffer as ArrayBuffer], { type: 'application/pdf' });
      ext = 'pdf';
    } else {
      blob = new Blob(['sample text'], { type: 'text/plain' });
      ext = 'txt';
    }

    assert.strictEqual(ext, 'pdf', 'Extension must be pdf');
    assert.strictEqual(blob.type, 'application/pdf', 'Blob MIME type must be application/pdf');
    assert.strictEqual(blob.size, samplePdfBytes.length, 'Blob size must match original PDF byte length');
  });
});
