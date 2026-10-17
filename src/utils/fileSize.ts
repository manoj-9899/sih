/**
 * Document File Size Detection & Human-Readable Formatting Utility.
 * 
 * SIH Problem Statement 26237
 * Provides consistent binary-unit (1024-based) formatting and size resolution
 * for protected documents, uploaded PDFs, packages, and forensic artifacts.
 */

import { ClassifiedDocument } from '../types';

/**
 * Formats an exact byte count into a standard human-readable binary-unit string.
 * Rules:
 * - Less than 1 KB (0 to 1023 B): display exact bytes, e.g. "850 B", "0 B"
 * - From 1 KB to less than 1 MB (1024 to 1,048,575 B): display KB with 1 decimal place, e.g. "150.0 KB"
 * - 1 MB or greater (>= 1,048,576 B): display MB with 2 decimal places, e.g. "2.00 MB"
 * - Invalid, undefined, null, or negative byte counts: "Size unavailable"
 */
export function formatFileSize(bytes?: number | null): string {
  if (typeof bytes !== 'number' || isNaN(bytes) || bytes < 0) {
    return 'Size unavailable';
  }

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Determines the document format label (PDF or TXT) based on MIME type,
 * binary presence, or filename extension.
 */
export function getDocumentFormatLabel(doc: ClassifiedDocument): string {
  if (
    doc.isPdf ||
    doc.mimeType === 'application/pdf' ||
    doc.filename?.toLowerCase().endsWith('.pdf') ||
    (doc.pdfBytes && doc.pdfBytes.byteLength > 0)
  ) {
    return 'PDF';
  }
  return 'TXT';
}

/**
 * Safely resolves the original document's byte length.
 * Priority order:
 * 1. Explicit `fileSizeBytes` property if valid number >= 0
 * 2. In-memory `pdfBytes` binary buffer length
 * 3. Encoded UTF-8 byte length of `rawText` (only for non-PDF documents)
 * 4. Fallback: undefined (will render "Size unavailable" instead of an invented number)
 */
export function getDocumentByteLength(doc: ClassifiedDocument): number | undefined {
  if (typeof doc.fileSizeBytes === 'number' && !isNaN(doc.fileSizeBytes) && doc.fileSizeBytes >= 0) {
    return doc.fileSizeBytes;
  }

  if (doc.pdfBytes && doc.pdfBytes.byteLength > 0) {
    return doc.pdfBytes.byteLength;
  }

  if (doc.rawText && typeof doc.rawText === 'string') {
    // If it's a PDF document with rawText placeholder like "[BINARY PDF DOCUMENT: ...]",
    // do not use TextEncoder on placeholder string.
    if (doc.isPdf || doc.mimeType === 'application/pdf') {
      return undefined;
    }
    return new TextEncoder().encode(doc.rawText).length;
  }

  return undefined;
}

/**
 * Formats a document's badge string containing format and actual size.
 * Examples:
 * - "PDF • 150.0 KB"
 * - "PDF • 2.00 MB"
 * - "PDF • 850 B"
 * - "TXT • 1.2 KB"
 * - "PDF • Size unavailable"
 */
export function formatDocumentBadge(doc: ClassifiedDocument): string {
  const format = getDocumentFormatLabel(doc);
  const sizeBytes = getDocumentByteLength(doc);
  const formattedSize = formatFileSize(sizeBytes);
  return `${format} • ${formattedSize}`;
}
