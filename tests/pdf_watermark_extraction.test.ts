import './setup.ts';
import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import { PDFDocument, PDFName, rgb } from 'pdf-lib';
import { embedWatermarkInPdf, extractWatermarkFromPdf } from '../src/watermark/engine.ts';
import { createMinimalValidPdf } from '../src/crypto/pdfUtils.ts';
import { WatermarkPayload } from '../src/types/index.ts';

describe('TEST GROUP 10: Blind PDF Forensic Watermark Extraction Engine (PDF-WM-EXTRACT-01 to PDF-WM-EXTRACT-10, False-Positive & Tampering)', () => {
  // Helper to generate a multi-page PDF
  async function createMultiPageTestPdf(): Promise<Uint8Array> {
    const doc = await PDFDocument.create();
    const p1 = doc.addPage([612, 792]);
    p1.drawText('CONFIDENTIAL MILITARY AIRSPACE LOG', { x: 50, y: 700, size: 14 });
    const p2 = doc.addPage([612, 792]);
    p2.drawText('RADAR FREQUENCIES AND TRANSPONDER CODES', { x: 50, y: 700, size: 12 });
    return await doc.save();
  }

  const payloadAlice: WatermarkPayload = {
    syncHeader: 0xa55a,
    sessionId: 'c3f4e2b1-9876-4321-abcd-ef0123456789',
    watermarkId: 'WM-C3F4E2B1',
    recipientId: 'RECIP-ALICE',
    recipientFingerprint: 'a1b2c3d4e5f60718',
    timestamp: 1790610000000,
    eccChecksum: 0,
  };

  const payloadBob: WatermarkPayload = {
    syncHeader: 0xa55a,
    sessionId: 'e8d7c6b5-1234-5678-fedc-ba9876543210',
    watermarkId: 'WM-E8D7C6B5',
    recipientId: 'RECIP-BOB',
    recipientFingerprint: 'b2c3d4e5f6071829',
    timestamp: 1790611000000,
    eccChecksum: 0,
  };

  it('PDF-WM-EXTRACT-01: Valid watermarked PDF returns the original watermark payload intact', async () => {
    const originalPdf = await createMultiPageTestPdf();
    const watermarkedPdf = await embedWatermarkInPdf(originalPdf, payloadAlice);

    const result = await extractWatermarkFromPdf(watermarkedPdf);

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.status, 'VALID_WATERMARK');
    assert.ok(result.payload, 'Payload must be returned');
    assert.strictEqual(result.crcVerified, true);
  });

  it('PDF-WM-EXTRACT-02: Session UUID is recovered correctly and matches exactly', async () => {
    const originalPdf = createMinimalValidPdf('Session UUID Test');
    const watermarkedPdf = await embedWatermarkInPdf(originalPdf, payloadAlice);

    const result = await extractWatermarkFromPdf(watermarkedPdf);

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.sessionId?.toLowerCase(), payloadAlice.sessionId.toLowerCase());
  });

  it('PDF-WM-EXTRACT-03: Recipient fingerprint is recovered correctly and matches exactly', async () => {
    const originalPdf = createMinimalValidPdf('Fingerprint Test');
    const watermarkedPdf = await embedWatermarkInPdf(originalPdf, payloadAlice);

    const result = await extractWatermarkFromPdf(watermarkedPdf);

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.recipientFingerprint?.toLowerCase(), payloadAlice.recipientFingerprint.toLowerCase());
  });

  it('PDF-WM-EXTRACT-04: Timestamp is recovered correctly (seconds resolution)', async () => {
    const originalPdf = createMinimalValidPdf('Timestamp Test');
    const watermarkedPdf = await embedWatermarkInPdf(originalPdf, payloadAlice);

    const result = await extractWatermarkFromPdf(watermarkedPdf);

    assert.strictEqual(result.success, true);
    assert.ok(result.timestamp, 'Timestamp must exist');
    // Timestamps serialize in seconds; verify within 1-second truncation
    const expectedSec = Math.floor(payloadAlice.timestamp / 1000);
    const recoveredSec = Math.floor(result.timestamp / 1000);
    assert.strictEqual(recoveredSec, expectedSec);
  });

  it('PDF-WM-EXTRACT-05: CRC-16 validation succeeds for an intact watermark', async () => {
    const originalPdf = createMinimalValidPdf('CRC Intact Test');
    const watermarkedPdf = await embedWatermarkInPdf(originalPdf, payloadAlice);

    const result = await extractWatermarkFromPdf(watermarkedPdf);

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.crcVerified, true);
    assert.strictEqual(result.status, 'VALID_WATERMARK');
  });

  it('PDF-WM-EXTRACT-06: PDF without a watermark returns NO_WATERMARK cleanly', async () => {
    const cleanPdf = await createMultiPageTestPdf();

    const result = await extractWatermarkFromPdf(cleanPdf);

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.status, 'NO_WATERMARK');
    assert.strictEqual(result.payload, undefined);
  });

  it('PDF-WM-EXTRACT-07: Corrupted payload fails CRC-16 validation (Tampering Detection)', async () => {
    const originalPdf = createMinimalValidPdf('Tamper Test');
    const watermarkedPdf = await embedWatermarkInPdf(originalPdf, payloadAlice);

    // Tamper with the PayloadHex inside the PDF dictionary
    const pdfDoc = await PDFDocument.load(watermarkedPdf);
    const ref = pdfDoc.catalog.get(PDFName.of('ForensicProvenance'));
    const dict = pdfDoc.context.lookup(ref) as any;

    const hexObj = dict.get(PDFName.of('PayloadHex'));
    const originalHex = (typeof hexObj.asString === 'function' ? hexObj.asString() : typeof hexObj.decodeText === 'function' ? hexObj.decodeText() : String(hexObj.value || hexObj)).replace(/[^0-9a-fA-F]/g, '');
    // Flip one character in the hex string (middle byte)
    const tamperedHex = originalHex.slice(0, 20) + (originalHex[20] === '0' ? '1' : '0') + originalHex.slice(21);
    dict.set(PDFName.of('PayloadHex'), pdfDoc.context.obj(tamperedHex));

    const tamperedPdfBytes = await pdfDoc.save();

    const result = await extractWatermarkFromPdf(tamperedPdfBytes);

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.status, 'CRC_FAILURE');
    assert.strictEqual(result.crcVerified, false);
    assert.match(result.error || '', /CRC-16 mismatch.*Tampering detected/i);
  });

  it('PDF-WM-EXTRACT-08: Invalid/truncated PDF is rejected safely without crashing', async () => {
    const truncatedBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]); // Only 5 bytes
    const result1 = await extractWatermarkFromPdf(truncatedBytes);
    assert.strictEqual(result1.success, false);
    assert.strictEqual(result1.status, 'INVALID_PDF');

    const randomBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const result2 = await extractWatermarkFromPdf(randomBytes);
    assert.strictEqual(result2.success, false);
    assert.strictEqual(result2.status, 'INVALID_PDF');
  });

  it('PDF-WM-EXTRACT-09: Two recipient PDFs produce two different recovered watermark payloads', async () => {
    const originalPdf = await createMultiPageTestPdf();
    const alicePdf = await embedWatermarkInPdf(originalPdf, payloadAlice);
    const bobPdf = await embedWatermarkInPdf(originalPdf, payloadBob);

    const aliceResult = await extractWatermarkFromPdf(alicePdf);
    const bobResult = await extractWatermarkFromPdf(bobPdf);

    assert.strictEqual(aliceResult.success, true);
    assert.strictEqual(bobResult.success, true);

    assert.notStrictEqual(aliceResult.sessionId, bobResult.sessionId);
    assert.notStrictEqual(aliceResult.recipientFingerprint, bobResult.recipientFingerprint);
    assert.notStrictEqual(aliceResult.watermarkId, bobResult.watermarkId);
  });

  it('PDF-WM-EXTRACT-10: Extraction is 100% blind (works without access to the original PDF)', async () => {
    const originalPdf = createMinimalValidPdf('Blind Extraction Proof');
    const watermarkedPdf = await embedWatermarkInPdf(originalPdf, payloadAlice);

    // Extraction function receives ONLY the leaked bytes
    const result = await extractWatermarkFromPdf(watermarkedPdf);

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.status, 'VALID_WATERMARK');
    assert.strictEqual(result.extractionSource, 'STRUCTURAL_CATALOG_ENCLAVE');
  });

  // ==========================================
  // FALSE-POSITIVE TESTS
  // ==========================================

  it('FALSE-POSITIVE-01: Standard PDF with ordinary Info metadata returns NO_WATERMARK', async () => {
    const doc = await PDFDocument.create();
    doc.setTitle('Standard Unclassified Whitepaper');
    doc.setAuthor('Dr. Mallory Random');
    doc.setSubject('Cryptographic Analysis');
    doc.setKeywords(['security', 'watermark', 'pqc']);
    const page = doc.addPage([612, 792]);
    page.drawText('Whitepaper content without forensic provenance.', { x: 50, y: 700 });
    const standardPdf = await doc.save();

    const result = await extractWatermarkFromPdf(standardPdf);

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.status, 'NO_WATERMARK');
  });

  it('FALSE-POSITIVE-02: PDF with visual text resembling a watermark string returns NO_WATERMARK', async () => {
    const doc = await PDFDocument.create();
    const page = doc.addPage([612, 792]);
    page.drawText('WM-C3F4E2B1 Session: c3f4e2b1-9876-4321-abcd-ef0123456789', { x: 50, y: 700 });
    const forgedVisualPdf = await doc.save();

    const result = await extractWatermarkFromPdf(forgedVisualPdf);

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.status, 'NO_WATERMARK');
  });

  it('FALSE-POSITIVE-03: PDF with random hex string in catalog returns MALFORMED_WATERMARK or INVALID_SYNC_WORD', async () => {
    const doc = await PDFDocument.create();
    doc.addPage([612, 792]);

    // Insert an arbitrary dictionary that lacks valid sync header or proper CRC
    const randomDict = doc.context.obj({
      Type: 'ForensicProvenance',
      PayloadHex: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    });
    doc.catalog.set(PDFName.of('ForensicProvenance'), doc.context.register(randomDict));
    const randomPdf = await doc.save();

    const result = await extractWatermarkFromPdf(randomPdf);

    assert.strictEqual(result.success, false);
    // Must fail sync word or CRC, never return VALID_WATERMARK
    assert.ok(
      result.status === 'INVALID_SYNC_WORD' || result.status === 'CRC_FAILURE' || result.status === 'MALFORMED_WATERMARK',
      `Result status was: ${result.status}`
    );
  });

  // ==========================================
  // TAMPERING TESTS
  // ==========================================

  it('TAMPER-01: Modifying stored CRC-16 fails verification', async () => {
    const originalPdf = createMinimalValidPdf('Tamper CRC Test');
    const watermarkedPdf = await embedWatermarkInPdf(originalPdf, payloadAlice);

    const pdfDoc = await PDFDocument.load(watermarkedPdf);
    const ref = pdfDoc.catalog.get(PDFName.of('ForensicProvenance'));
    const dict = pdfDoc.context.lookup(ref) as any;
    const hexObj = dict.get(PDFName.of('PayloadHex'));
    const hex = (typeof hexObj.asString === 'function' ? hexObj.asString() : typeof hexObj.decodeText === 'function' ? hexObj.decodeText() : String(hexObj.value || hexObj)).replace(/[^0-9a-fA-F]/g, '');

    // The last 4 characters are the CRC16 hex (bytes 30..31)
    const tamperedHex = hex.slice(0, 60) + 'ffff';
    dict.set(PDFName.of('PayloadHex'), pdfDoc.context.obj(tamperedHex));
    const tamperedPdf = await pdfDoc.save();

    const result = await extractWatermarkFromPdf(tamperedPdf);

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.status, 'CRC_FAILURE');
  });

  it('TAMPER-02: Modifying sync word (bytes 0..1) fails verification', async () => {
    const originalPdf = createMinimalValidPdf('Tamper Sync Test');
    const watermarkedPdf = await embedWatermarkInPdf(originalPdf, payloadAlice);

    const pdfDoc = await PDFDocument.load(watermarkedPdf);
    const ref = pdfDoc.catalog.get(PDFName.of('ForensicProvenance'));
    const dict = pdfDoc.context.lookup(ref) as any;
    const hexObj = dict.get(PDFName.of('PayloadHex'));
    const hex = (typeof hexObj.asString === 'function' ? hexObj.asString() : typeof hexObj.decodeText === 'function' ? hexObj.decodeText() : String(hexObj.value || hexObj)).replace(/[^0-9a-fA-F]/g, '');

    // Bytes 0..1 are the sync header 0xA55A
    const tamperedHex = '0000' + hex.slice(4);
    dict.set(PDFName.of('PayloadHex'), pdfDoc.context.obj(tamperedHex));
    const tamperedPdf = await pdfDoc.save();

    const result = await extractWatermarkFromPdf(tamperedPdf);

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.status, 'INVALID_SYNC_WORD');
  });

  it('TAMPER-03: Truncating payload length fails verification with MALFORMED_WATERMARK', async () => {
    const originalPdf = createMinimalValidPdf('Truncate Payload Test');
    const watermarkedPdf = await embedWatermarkInPdf(originalPdf, payloadAlice);

    const pdfDoc = await PDFDocument.load(watermarkedPdf);
    const ref = pdfDoc.catalog.get(PDFName.of('ForensicProvenance'));
    const dict = pdfDoc.context.lookup(ref) as any;

    // Provide only 32 hex chars (16 bytes) instead of 64 hex chars (32 bytes)
    dict.set(PDFName.of('PayloadHex'), pdfDoc.context.obj('a55a112233445566778899aabbccddeeff'));
    const tamperedPdf = await pdfDoc.save();

    const result = await extractWatermarkFromPdf(tamperedPdf);

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.status, 'MALFORMED_WATERMARK');
  });
});
