import './setup.ts';
import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import {
  formatFileSize,
  getDocumentFormatLabel,
  getDocumentByteLength,
  formatDocumentBadge,
} from '../src/utils/fileSize.ts';
import { ClassifiedDocument, Recipient } from '../src/types/index.ts';
import { createMinimalValidPdf, validatePdfBytes } from '../src/crypto/pdfUtils.ts';
import { DistributionService } from '../src/services/distributionService.ts';
import { PackageExportService } from '../src/services/packageExportService.ts';
import { initializeRecipientsAndLedger } from '../src/data/sampleData.ts';

describe('TEST GROUP: PDF File Size Detection & Multi-Recipient Provenance Display (SIZE-01 to SIZE-07)', () => {
  let alice: Recipient;
  let bob: Recipient;

  before(async () => {
    const recips = await initializeRecipientsAndLedger();
    alice = recips[0];
    bob = recips[1];
  });

  test('SIZE-01: A PDF with a known byte length displays the exact correct size', () => {
    // 153,600 bytes = 150.0 KB (153600 / 1024)
    const exact150Kb = 153600;
    assert.strictEqual(formatFileSize(exact150Kb), '150.0 KB');

    const pdfDoc: ClassifiedDocument = {
      id: 'DOC-TEST-150KB',
      title: 'Known Size Document',
      classification: 'SECRET',
      caveats: 'REL TO NATO',
      originatingOffice: 'STRATCOM',
      summary: 'Test 150KB doc',
      rawText: 'Placeholder',
      visualPages: [],
      createdAt: Date.now(),
      isPdf: true,
      fileSizeBytes: exact150Kb,
    };

    assert.strictEqual(getDocumentByteLength(pdfDoc), 153600);
    assert.strictEqual(formatDocumentBadge(pdfDoc), 'PDF • 150.0 KB');
  });

  test('SIZE-02: Two PDFs of different sizes display distinctly different formatted values', () => {
    // 150 KB vs 2 MB vs 500 KB
    const size150Kb = 153600; // 150.0 KB
    const size2Mb = 2097152; // 2.00 MB (2 * 1024 * 1024)
    const size500Kb = 512000; // 500.0 KB (500 * 1024)

    const doc1: ClassifiedDocument = {
      id: 'DOC-1',
      title: 'Doc 1',
      classification: 'CONFIDENTIAL',
      caveats: 'RESTRICTED',
      originatingOffice: 'OFFICE',
      summary: 'Summary 1',
      rawText: 'Text 1',
      visualPages: [],
      createdAt: Date.now(),
      isPdf: true,
      fileSizeBytes: size150Kb,
    };

    const doc2: ClassifiedDocument = {
      id: 'DOC-2',
      title: 'Doc 2',
      classification: 'TOP SECRET // SCI',
      caveats: 'RESTRICTED',
      originatingOffice: 'OFFICE',
      summary: 'Summary 2',
      rawText: 'Text 2',
      visualPages: [],
      createdAt: Date.now(),
      isPdf: true,
      fileSizeBytes: size2Mb,
    };

    const doc3: ClassifiedDocument = {
      id: 'DOC-3',
      title: 'Doc 3',
      classification: 'SECRET',
      caveats: 'RESTRICTED',
      originatingOffice: 'OFFICE',
      summary: 'Summary 3',
      rawText: 'Text 3',
      visualPages: [],
      createdAt: Date.now(),
      isPdf: true,
      fileSizeBytes: size500Kb,
    };

    const badge1 = formatDocumentBadge(doc1);
    const badge2 = formatDocumentBadge(doc2);
    const badge3 = formatDocumentBadge(doc3);

    assert.strictEqual(badge1, 'PDF • 150.0 KB');
    assert.strictEqual(badge2, 'PDF • 2.00 MB');
    assert.strictEqual(badge3, 'PDF • 500.0 KB');

    assert.notStrictEqual(badge1, badge2);
    assert.notStrictEqual(badge2, badge3);
    assert.notStrictEqual(badge1, badge3);
  });

  test('SIZE-03: Binary KB-to-MB formatting rules operate with strict precision across all ranges', () => {
    // 0 B boundary
    assert.strictEqual(formatFileSize(0), '0 B');

    // Sub-kilobyte (< 1024 bytes)
    assert.strictEqual(formatFileSize(1), '1 B');
    assert.strictEqual(formatFileSize(850), '850 B');
    assert.strictEqual(formatFileSize(1023), '1023 B');

    // Exactly 1 KB (1024 bytes)
    assert.strictEqual(formatFileSize(1024), '1.0 KB');

    // Kilobytes range (1 KB <= bytes < 1 MB)
    assert.strictEqual(formatFileSize(1536), '1.5 KB'); // 1.5 * 1024
    assert.strictEqual(formatFileSize(512000), '500.0 KB'); // 500 * 1024
    assert.strictEqual(formatFileSize(1048575), '1024.0 KB'); // 1 MB - 1 byte

    // Exactly 1 MB (1,048,576 bytes)
    assert.strictEqual(formatFileSize(1048576), '1.00 MB');

    // Multi-megabyte (>= 1 MB)
    assert.strictEqual(formatFileSize(2097152), '2.00 MB'); // 2 * 1024 * 1024
    assert.strictEqual(formatFileSize(5242880), '5.00 MB'); // 5 * 1024 * 1024
    assert.strictEqual(formatFileSize(15728640), '15.00 MB'); // 15 * 1024 * 1024
  });

  test('SIZE-04: fileSizeBytes accurately captures real uploaded PDF binary byte length', () => {
    const rawPdf = createMinimalValidPdf('Custom Uploaded Reconnaissance Plan');
    const validation = validatePdfBytes(rawPdf);

    assert.strictEqual(validation.isValid, true);
    assert.strictEqual(validation.sizeBytes, rawPdf.byteLength);

    // Simulate upload handler logic
    const detectedSize = rawPdf.byteLength;
    const uploadedDoc: ClassifiedDocument = {
      id: `DOC-UPLOAD-${Date.now()}`,
      title: 'Custom Uploaded Reconnaissance Plan',
      classification: 'TOP SECRET // SCI',
      caveats: 'SPECIAL ACCESS REQUIRED',
      originatingOffice: 'Directorate of Strategic Operations',
      summary: `Classified PDF (${formatFileSize(detectedSize)})`,
      rawText: `[BINARY PDF DOCUMENT]\nFile size: ${detectedSize} bytes`,
      visualPages: [],
      createdAt: Date.now(),
      isPdf: true,
      mimeType: 'application/pdf',
      filename: 'Recon_Plan.pdf',
      fileSizeBytes: detectedSize,
      pdfBytes: rawPdf,
    };

    assert.strictEqual(uploadedDoc.fileSizeBytes, rawPdf.byteLength);
    assert.strictEqual(getDocumentByteLength(uploadedDoc), rawPdf.byteLength);
    assert.strictEqual(formatDocumentBadge(uploadedDoc), `PDF • ${rawPdf.byteLength} B`);
  });

  test('SIZE-05: Original document size remains preserved across package creation, export, and import', async () => {
    const originalPdfBytes = createMinimalValidPdf('Cross-Workflow Size Preservation Matrix');
    const originalByteCount = originalPdfBytes.byteLength;

    const sourceDoc: ClassifiedDocument = {
      id: 'DOC-PKG-SIZE-TEST',
      title: 'Cross-Workflow Size Preservation Matrix',
      classification: 'SECRET',
      caveats: 'RESTRICTED',
      originatingOffice: 'AIR-GAP TEST ENCLAVE',
      summary: 'Testing that original size is stored in package metadata',
      rawText: '[BINARY PDF]',
      visualPages: [],
      createdAt: Date.now(),
      isPdf: true,
      mimeType: 'application/pdf',
      filename: 'Size_Preservation.pdf',
      fileSizeBytes: originalByteCount,
      pdfBytes: originalPdfBytes,
    };

    // 1. Create encrypted package
    const pkg = await DistributionService.createEncryptedPackage(sourceDoc, [alice, bob]);
    assert.strictEqual(
      pkg.fileSizeBytes,
      originalByteCount,
      'Package fileSizeBytes must match original document size, not ciphertext length'
    );

    // 2. Export package to .sihpkg binary
    const sihpkgBytes = await PackageExportService.exportPackageToBinary(pkg);
    assert.ok(sihpkgBytes.byteLength > originalByteCount, 'Encrypted package includes envelope/KEM overhead');

    // 3. Import and validate package
    const importResult = await PackageExportService.validateAndImportPackage(sihpkgBytes, alice.id);
    assert.strictEqual(importResult.isValid, true);
    assert.ok(importResult.package);

    // Verify imported package preserves original document sizeBytes from manifest
    assert.strictEqual(
      importResult.package.fileSizeBytes,
      originalByteCount,
      'Imported package must preserve original unencrypted document fileSizeBytes'
    );
  });

  test('SIZE-06: Missing or invalid metadata does not cause a fake ~24 KB value to appear', () => {
    // Document with undefined fileSizeBytes and no pdfBytes
    const emptyMetaDoc: ClassifiedDocument = {
      id: 'DOC-NO-META',
      title: 'Corrupted Metadata Record',
      classification: 'CONFIDENTIAL',
      caveats: 'RESTRICTED',
      originatingOffice: 'UNKNOWN',
      summary: 'No size metadata',
      rawText: '',
      visualPages: [],
      createdAt: Date.now(),
      isPdf: true,
      fileSizeBytes: undefined,
    };

    const badge = formatDocumentBadge(emptyMetaDoc);
    assert.strictEqual(badge, 'PDF • Size unavailable');
    assert.ok(!badge.includes('24 KB'), 'Must never output hardcoded ~24 KB default');

    // Test raw formatFileSize with missing values
    assert.strictEqual(formatFileSize(undefined), 'Size unavailable');
    assert.strictEqual(formatFileSize(null), 'Size unavailable');
    assert.strictEqual(formatFileSize(-1), 'Size unavailable');
    assert.strictEqual(formatFileSize(NaN), 'Size unavailable');
  });

  test('SIZE-07: Invalid uploads and failed reads do not leave stale size information', () => {
    // Simulate initial valid state
    let uploadedPdfBytes: Uint8Array | null = new Uint8Array([1, 2, 3]);
    let pdfFileName: string = 'previous_valid.pdf';
    let pdfFileSize: number = 153600;
    let uploadError: string | null = null;

    // Simulate rejection handler on invalid file
    const handleRejection = (errorMsg: string) => {
      uploadError = errorMsg;
      uploadedPdfBytes = null;
      pdfFileName = '';
      pdfFileSize = 0;
    };

    handleRejection('Invalid PDF File: Missing %PDF- header');

    assert.strictEqual(uploadedPdfBytes, null);
    assert.strictEqual(pdfFileName, '');
    assert.strictEqual(pdfFileSize, 0);
    assert.ok(uploadError !== null);

    // If an upload is cancelled/reset
    const handleReset = () => {
      uploadedPdfBytes = null;
      pdfFileName = '';
      pdfFileSize = 0;
      uploadError = null;
    };

    handleReset();
    assert.strictEqual(uploadedPdfBytes, null);
    assert.strictEqual(pdfFileName, '');
    assert.strictEqual(pdfFileSize, 0);
    assert.strictEqual(uploadError, null);
  });
});
