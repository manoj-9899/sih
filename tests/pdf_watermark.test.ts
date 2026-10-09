import './setup.ts';
import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import { PDFDocument, rgb } from 'pdf-lib';
import { embedWatermarkInPdf } from '../src/watermark/engine.ts';
import { validatePdfBytes, createMinimalValidPdf } from '../src/crypto/pdfUtils.ts';
import { WatermarkPayload } from '../src/types/index.ts';

describe('TEST GROUP 9: Real PDF Forensic Watermark Embedding Engine (PDF-WM-EMBED-01 to PDF-WM-EMBED-09)', () => {
  // Helper to construct a multi-page PDF with shapes and text using pdf-lib
  async function createMultiPageTestPdf(): Promise<Uint8Array> {
    const doc = await PDFDocument.create();
    
    // Page 1
    const page1 = doc.addPage([612, 792]);
    page1.drawText('TOP SECRET // SCI DEFENSE EVALUATION', { x: 50, y: 700, size: 16 });
    page1.drawRectangle({ x: 50, y: 650, width: 200, height: 40, color: rgb(0.1, 0.2, 0.4) });

    // Page 2
    const page2 = doc.addPage([612, 792]);
    page2.drawText('TACTICAL FREQUENCY ALLOCATION MATRIX', { x: 50, y: 700, size: 14 });

    // Page 3 (Landscape)
    const page3 = doc.addPage([792, 612]);
    page3.drawText('CRITICAL NETWORK TOPOLOGY', { x: 50, y: 550, size: 14 });

    return await doc.save();
  }

  const payloadAlice: WatermarkPayload = {
    syncHeader: 0xa55a,
    sessionId: 'c3f4e2b1-9876-4321-abcd-ef0123456789',
    watermarkId: 'WM-ALICE-01',
    recipientId: 'RECIP-ALICE',
    recipientFingerprint: 'A1B2C3D4E5F60718',
    timestamp: 1790610000000,
    eccChecksum: 0,
  };

  const payloadBob: WatermarkPayload = {
    syncHeader: 0xa55a,
    sessionId: 'e8d7c6b5-1234-5678-fedc-ba9876543210',
    watermarkId: 'WM-BOB-02',
    recipientId: 'RECIP-BOB',
    recipientFingerprint: 'B2C3D4E5F6071829',
    timestamp: 1790611000000,
    eccChecksum: 0,
  };

  it('PDF-WM-EMBED-01: Valid PDF can be loaded and watermarked without error', async () => {
    const originalPdf = createMinimalValidPdf('Confidential Evaluation');
    const watermarked = await embedWatermarkInPdf(originalPdf, payloadAlice);

    assert.ok(watermarked instanceof Uint8Array, 'Result must be a Uint8Array');
    assert.ok(watermarked.length > 0, 'Watermarked output must not be empty');
  });

  it('PDF-WM-EMBED-02: Watermarked output remains a strictly valid PDF', async () => {
    const originalPdf = createMinimalValidPdf('Strict Validation Test');
    const watermarked = await embedWatermarkInPdf(originalPdf, payloadAlice);

    const validation = validatePdfBytes(watermarked);
    assert.strictEqual(validation.isValid, true, 'Output must have valid %PDF- header');
    assert.strictEqual(validation.sizeBytes, watermarked.length);
  });

  it('PDF-WM-EMBED-03: Watermarked PDF can be loaded and parsed again by PDFDocument', async () => {
    const originalPdf = createMinimalValidPdf('Reloadability Verification');
    const watermarked = await embedWatermarkInPdf(originalPdf, payloadAlice);

    // Attempt reload with pdf-lib
    const reloadedDoc = await PDFDocument.load(watermarked);
    assert.ok(reloadedDoc, 'Watermarked PDF must reload cleanly');
    assert.ok(reloadedDoc.getPageCount() > 0, 'Must have at least one page');
  });

  it('PDF-WM-EMBED-04: Page count is preserved exactly before and after watermarking', async () => {
    const multiPdf = await createMultiPageTestPdf();
    const originalDoc = await PDFDocument.load(multiPdf);
    const originalPageCount = originalDoc.getPageCount();
    assert.strictEqual(originalPageCount, 3, 'Original must have 3 pages');

    const watermarked = await embedWatermarkInPdf(multiPdf, payloadAlice);
    const watermarkedDoc = await PDFDocument.load(watermarked);

    assert.strictEqual(
      watermarkedDoc.getPageCount(),
      originalPageCount,
      'Page count must remain exactly 3 after watermarking'
    );
  });

  it('PDF-WM-EMBED-05: Page dimensions and orientations are unchanged', async () => {
    const multiPdf = await createMultiPageTestPdf();
    const watermarked = await embedWatermarkInPdf(multiPdf, payloadAlice);

    const watermarkedDoc = await PDFDocument.load(watermarked);
    const pages = watermarkedDoc.getPages();

    // Page 1: Portrait 612 x 792
    assert.strictEqual(pages[0].getWidth(), 612);
    assert.strictEqual(pages[0].getHeight(), 792);

    // Page 2: Portrait 612 x 792
    assert.strictEqual(pages[1].getWidth(), 612);
    assert.strictEqual(pages[1].getHeight(), 792);

    // Page 3: Landscape 792 x 612
    assert.strictEqual(pages[2].getWidth(), 792);
    assert.strictEqual(pages[2].getHeight(), 612);
  });

  it('PDF-WM-EMBED-06: Two different watermark payloads produce different output files', async () => {
    const basePdf = await createMultiPageTestPdf();

    const aliceWatermarked = await embedWatermarkInPdf(basePdf, payloadAlice);
    const bobWatermarked = await embedWatermarkInPdf(basePdf, payloadBob);

    // Check that Alice and Bob received distinct binary copies
    assert.notStrictEqual(
      Buffer.from(aliceWatermarked).toString('hex'),
      Buffer.from(bobWatermarked).toString('hex'),
      'Alice and Bob copies must be forensically distinct'
    );
  });

  it('PDF-WM-EMBED-07: Same payload produces a valid, expected structural enclave', async () => {
    const basePdf = createMinimalValidPdf('Structural Enclave Test');
    const watermarked = await embedWatermarkInPdf(basePdf, payloadAlice);

    // Inspect the internal PDF catalog object to verify the structural enclave
    const doc = await PDFDocument.load(watermarked);
    const catalog = doc.catalog;
    
    // ForensicProvenance dictionary entry must exist in catalog
    assert.ok(catalog.has(doc.context.obj('ForensicProvenance')), 'ForensicProvenance entry must exist in catalog');
  });

  it('PDF-WM-EMBED-08: Watermark embedding does not throw on a valid multi-page PDF', async () => {
    const multiPdf = await createMultiPageTestPdf();
    await assert.doesNotReject(async () => {
      await embedWatermarkInPdf(multiPdf, payloadAlice);
    }, 'Embedding into multi-page PDF must succeed cleanly');
  });

  it('PDF-WM-EMBED-09: Invalid/truncated PDF is rejected safely with error', async () => {
    const invalidBuffer = new Uint8Array([1, 2, 3, 4, 5]);

    await assert.rejects(
      async () => {
        await embedWatermarkInPdf(invalidBuffer, payloadAlice);
      },
      /PDF Watermarking Error/,
      'Invalid input buffer must be rejected with descriptive error'
    );
  });
});
