/**
 * PDF Binary Utilities & Header Validation.
 * 
 * Provides robust client-side validation of real PDF binary streams.
 * Enforces magic header checks (%PDF-1.x) rather than relying on file extensions.
 */

import { sha256Hex } from './pqc';

// Standard PDF magic byte sequence: "%PDF-" (ASCII 0x25, 0x50, 0x44, 0x46, 0x2D)
const PDF_MAGIC_BYTES = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]);

export interface PdfValidationResult {
  isValid: boolean;
  version?: string;
  sizeBytes: number;
  error?: string;
}

/**
 * Validates whether a raw byte buffer is a genuine PDF file by inspecting
 * the binary magic header within the first 1024 bytes.
 * 
 * Per ISO 32000-1 (PDF specification), the %PDF-n.m header must appear within
 * the first 1024 bytes of the file.
 */
export function validatePdfBytes(bytes: Uint8Array): PdfValidationResult {
  if (!bytes || !(bytes instanceof Uint8Array)) {
    return {
      isValid: false,
      sizeBytes: 0,
      error: 'Invalid input: Buffer must be a valid Uint8Array.',
    };
  }

  if (bytes.length < 8) {
    return {
      isValid: false,
      sizeBytes: bytes.length,
      error: 'File too small: Buffer must be at least 8 bytes to contain a PDF header.',
    };
  }

  // Scan the first 1024 bytes (or buffer length) for the %PDF- signature
  const maxScan = Math.min(bytes.length, 1024);
  let headerIndex = -1;

  for (let i = 0; i <= maxScan - 5; i++) {
    if (
      bytes[i] === PDF_MAGIC_BYTES[0] &&
      bytes[i + 1] === PDF_MAGIC_BYTES[1] &&
      bytes[i + 2] === PDF_MAGIC_BYTES[2] &&
      bytes[i + 3] === PDF_MAGIC_BYTES[3] &&
      bytes[i + 4] === PDF_MAGIC_BYTES[4]
    ) {
      headerIndex = i;
      break;
    }
  }

  if (headerIndex === -1) {
    return {
      isValid: false,
      sizeBytes: bytes.length,
      error: 'Invalid PDF: Missing standard %PDF- header in initial bytes.',
    };
  }

  // Extract version string (e.g. "1.4", "1.7", "2.0")
  let version = '1.4';
  try {
    const headerSlice = bytes.slice(headerIndex, headerIndex + 12);
    const headerStr = new TextDecoder('ascii').decode(headerSlice);
    const match = headerStr.match(/%PDF-([0-9]\.[0-9])/);
    if (match) {
      version = match[1];
    }
  } catch (_e) {
    // Default fallback
  }

  return {
    isValid: true,
    version,
    sizeBytes: bytes.length,
  };
}

/**
 * Computes canonical cryptographic SHA-256 hash directly over original PDF binary bytes.
 */
export async function computePdfBinaryHashSha256(bytes: Uint8Array): Promise<string> {
  if (!bytes || bytes.length === 0) {
    throw new Error('Cannot compute hash: byte buffer is empty or undefined.');
  }
  return await sha256Hex(bytes);
}

/**
 * Helper to generate a minimal, valid, standalone PDF 1.4 binary Uint8Array in memory.
 * Useful for deterministic testing, fallbacks, and demonstration documents.
 */
export function createMinimalValidPdf(title = 'Confidential Report'): Uint8Array {
  const content = `BT /F1 14 Tf 50 750 Td (${title.replace(/[()\\]/g, '')}) Tj ET`;
  const streamLen = content.length;

  const pdfString = [
    '%PDF-1.4',
    '1 0 obj',
    '<< /Type /Catalog /Pages 2 0 R >>',
    'endobj',
    '2 0 obj',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    'endobj',
    '3 0 obj',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    'endobj',
    '4 0 obj',
    `<< /Length ${streamLen} >>`,
    'stream',
    content,
    'endstream',
    'endobj',
    '5 0 obj',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    'endobj',
    'xref',
    '0 6',
    '0000000000 65535 f ',
    '0000000009 00000 n ',
    '0000000058 00000 n ',
    '0000000115 00000 n ',
    '0000000251 00000 n ',
    '0000000346 00000 n ',
    'trailer',
    '<< /Size 6 /Root 1 0 R >>',
    'startxref',
    '429',
    '%%EOF\n',
  ].join('\n');

  return new TextEncoder().encode(pdfString);
}
