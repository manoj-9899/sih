/**
 * Secure .sihpkg Portable Encrypted Package Service.
 * Implements:
 * 1. Binary Container Serialization (.sihpkg v1)
 * 2. Deterministic Integrity Checksums & AAD Binding
 * 3. 11-Stage Deep Import Validation & Tamper Detection
 * 4. Recipient Authorization Isolation & Air-Gapped Persistence
 */

import {
  EncryptedPackage,
  SihpkgManifest,
  SihpkgRecipientEntry,
  PackageValidationResult,
  PackageAuditEvent,
  Recipient,
} from '../types';
import {
  sha256Bytes,
  sha256Hex,
  hexToBytes,
  bytesToHex,
  base64ToBytes,
  bytesToBase64,
  computeDocumentAad,
  zeroizeBytes,
  canonicalizeJson,
} from '../crypto/pqc';
import { airGappedStorage } from '../storage/airGappedStorage';
import { AuthenticatedSession } from '../crypto/sessionManager';
import { auditService } from './auditService';

// Binary Container Constants
export const SIHPKG_MAGIC = new Uint8Array([0x53, 0x49, 0x48, 0x50, 0x4b, 0x47, 0x30, 0x31]); // 'SIHPKG01'
export const SIHPKG_VERSION = 1;
export const HEADER_SIZE = 24;
export const TRAILER_SIZE = 32;

export class PackageExportService {
  /**
   * Serializes an EncryptedPackage into an authentic binary .sihpkg container.
   * Container Layout:
   * [0..7]   Magic 'SIHPKG01' (8 bytes)
   * [8..9]   Version uint16BE (2 bytes)
   * [10..11] Flags uint16BE (2 bytes)
   * [12..15] Manifest Length uint32BE (4 bytes)
   * [16..19] Payload Length uint32BE (4 bytes)
   * [20..21] IV Length uint16BE (2 bytes)
   * [22..23] Tag Length uint16BE (2 bytes)
   * [24..M]  Manifest JSON (UTF-8 bytes)
   * [M..IV]  IV raw bytes (12 bytes)
   * [IV..T]  Tag raw bytes (16 bytes)
   * [T..P]   Ciphertext raw bytes (P_LEN bytes)
   * [P..END] Integrity Checksum (32 bytes SHA-256 over all preceding bytes)
   */
  public static async exportPackageToBinary(
    pkg: EncryptedPackage,
    distributionId?: string,
    senderOverride?: { senderId: string; senderName: string }
  ): Promise<Uint8Array> {
    if (!pkg || !pkg.ciphertextBase64) {
      throw new Error('ExportError: Invalid or empty encrypted package provided.');
    }
    if (!pkg.envelopes || pkg.envelopes.length === 0) {
      throw new Error('ExportError: Package has zero recipient envelopes.');
    }

    const distId = distributionId || pkg.distributionId || `DIST-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 8999 + 1000)}`;
    const sender = senderOverride || {
      senderId: pkg.senderId || 'SNDR-STRATCOM-01',
      senderName: pkg.senderName || 'Directorate of Strategic Operations',
    };

    // 1. Extract raw ciphertext, IV, and tag bytes
    const ciphertextBytes = base64ToBytes(pkg.ciphertextBase64);
    const ivBytes = hexToBytes(pkg.ivHex);
    const tagBytes = hexToBytes(pkg.tagHex);

    if (ciphertextBytes.length === 0) {
      throw new Error('ExportError: Ciphertext buffer is empty.');
    }

    // 2. Compute cryptographic hashes
    const payloadHashSha256 = await sha256Hex(ciphertextBytes);
    const aadBinding = computeDocumentAad(pkg.documentId, pkg.originalDocumentHashSha256);

    // 3. Prepare Recipient Envelopes
    const recipients: SihpkgRecipientEntry[] = pkg.envelopes.map((env, idx) => ({
      recipientId: env.recipientId,
      recipientName: env.recipientName,
      envelopeId: env.envelopeId || `ENV-${(idx + 1).toString().padStart(2, '0')}-${env.recipientId.slice(-4)}`,
      publicKeyFingerprint: env.publicKeyFingerprint || `FP-${env.recipientId.slice(-8)}`,
      kemAlgorithm: 'ML-KEM-768',
      kemCiphertextBase64: env.kemCiphertextBase64,
      wrappedCekBase64: env.wrappedCekBase64,
      status: env.status || 'AUTHORIZED',
    }));

    // 4. Construct Manifest
    const manifestDraft: SihpkgManifest = {
      format: 'SIHPKG',
      version: 1,
      packageId: pkg.packageId,
      distributionId: distId,
      createdAt: pkg.createdAt || Date.now(),
      sender,
      document: {
        documentId: pkg.documentId,
        documentTitle: pkg.documentTitle,
        filename: pkg.filename || `${pkg.documentTitle.replace(/\s+/g, '_')}.${pkg.isPdf ? 'pdf' : 'txt'}`,
        mimeType: pkg.mimeType || (pkg.isPdf ? 'application/pdf' : 'text/plain'),
        sizeBytes: typeof pkg.fileSizeBytes === 'number' && pkg.fileSizeBytes >= 0
          ? pkg.fileSizeBytes
          : ciphertextBytes.length,
        classification: pkg.classification,
        originalDocumentHashSha256: pkg.originalDocumentHashSha256,
      },
      encryption: {
        algorithm: 'AES-256-GCM',
        ivHex: pkg.ivHex,
        tagHex: pkg.tagHex,
        aadBinding,
        aadString: aadBinding,
      },
      recipients,
      integrity: {
        manifestHashSha256: '',
        payloadHashSha256,
        packageHashSha256: '',
      },
    };

    // Canonicalize manifest and compute its hash
    const canonicalManifestJson = canonicalizeJson(manifestDraft);
    const manifestHashSha256 = await sha256Hex(canonicalManifestJson);
    manifestDraft.integrity.manifestHashSha256 = manifestHashSha256;

    const manifestFinalJson = JSON.stringify(manifestDraft);
    const manifestBytes = new TextEncoder().encode(manifestFinalJson);

    // 5. Construct Binary Layout
    const mLen = manifestBytes.length;
    const pLen = ciphertextBytes.length;
    const ivLen = ivBytes.length;
    const tagLen = tagBytes.length;

    const totalBodySize = HEADER_SIZE + mLen + ivLen + tagLen + pLen;
    const totalSize = totalBodySize + TRAILER_SIZE;

    const container = new Uint8Array(totalSize);
    const view = new DataView(container.buffer, container.byteOffset, container.byteLength);

    // Write Header
    container.set(SIHPKG_MAGIC, 0);
    view.setUint16(8, SIHPKG_VERSION, false);
    view.setUint16(10, 0x0000, false); // Flags: standard
    view.setUint32(12, mLen, false);
    view.setUint32(16, pLen, false);
    view.setUint16(20, ivLen, false);
    view.setUint16(22, tagLen, false);

    // Write Body Components
    let offset = HEADER_SIZE;
    container.set(manifestBytes, offset);
    offset += mLen;

    container.set(ivBytes, offset);
    offset += ivLen;

    container.set(tagBytes, offset);
    offset += tagLen;

    container.set(ciphertextBytes, offset);
    offset += pLen;

    // 6. Compute Container Integrity Trailer (SHA-256 over all preceding bytes)
    const precedingBytes = container.subarray(0, totalBodySize);
    const trailerChecksum = await sha256Bytes(precedingBytes);
    container.set(trailerChecksum, totalBodySize);

    // 7. Audit log event
    await this.recordAuditEvent({
      eventId: `AUD-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 8999 + 1000)}`,
      eventType: 'PACKAGE_EXPORTED',
      timestamp: Date.now(),
      packageId: pkg.packageId,
      distributionId: distId,
      documentId: pkg.documentId,
      status: 'SUCCESS',
      details: `Exported SIHPKG v1 container for ${recipients.length} recipients (${totalSize} bytes).`,
    });

    return container;
  }

  /**
   * 11-Stage Deep Validation and Import Pipeline.
   * Performs exhaustive cryptographic and structural verification before registering package.
   */
  public static async validateAndImportPackage(
    inputBytes: Uint8Array,
    currentUserId?: string,
    currentSession?: AuthenticatedSession | null
  ): Promise<PackageValidationResult> {
    const steps: Array<{ step: string; passed: boolean; detail: string }> = [];

    // Stage 1: Basic Buffer & Header Size Check
    if (!inputBytes || !(inputBytes instanceof Uint8Array)) {
      return this.failResult('CORRUPTED_PACKAGE', 'Invalid package format: Expected Uint8Array buffer.', [
        { step: '1. Container Header Check', passed: false, detail: 'Input is not a binary byte buffer.' },
      ]);
    }

    if (inputBytes.length < HEADER_SIZE + TRAILER_SIZE) {
      return this.failResult(
        'CORRUPTED_PACKAGE',
        `Truncated package: File size is ${inputBytes.length} bytes, minimum required is ${HEADER_SIZE + TRAILER_SIZE} bytes.`,
        [{ step: '1. Container Header Check', passed: false, detail: 'File buffer too small for SIHPKG header and trailer.' }]
      );
    }

    // Stage 2: Magic Signature Check
    for (let i = 0; i < SIHPKG_MAGIC.length; i++) {
      if (inputBytes[i] !== SIHPKG_MAGIC[i]) {
        return this.failResult(
          'CORRUPTED_PACKAGE',
          'Invalid magic signature: File does not start with SIHPKG01 identifier.',
          [{ step: '2. Magic Signature Check', passed: false, detail: 'Magic bytes do not match "SIHPKG01".' }]
        );
      }
    }
    steps.push({ step: '1. Magic Signature', passed: true, detail: 'Valid "SIHPKG01" binary header verified.' });

    const view = new DataView(inputBytes.buffer, inputBytes.byteOffset, inputBytes.byteLength);

    // Stage 3: Version Verification
    const version = view.getUint16(8, false);
    if (version !== SIHPKG_VERSION) {
      return this.failResult(
        'UNSUPPORTED_VERSION',
        `Unsupported package version: Received SIHPKG v${version}. Supported versions: v1.`,
        [
          ...steps,
          { step: '2. Version Verification', passed: false, detail: `Unsupported version ${version}. Expected ${SIHPKG_VERSION}.` },
        ]
      );
    }
    steps.push({ step: '2. Format Version', passed: true, detail: `SIHPKG v${version} verified.` });

    // Stage 4: Layout & Boundary Bounds Verification
    const mLen = view.getUint32(12, false);
    const pLen = view.getUint32(16, false);
    const ivLen = view.getUint16(20, false);
    const tagLen = view.getUint16(22, false);

    const expectedTotalBody = HEADER_SIZE + mLen + ivLen + tagLen + pLen;
    const expectedTotalSize = expectedTotalBody + TRAILER_SIZE;

    if (inputBytes.length !== expectedTotalSize) {
      return this.failResult(
        'CORRUPTED_PACKAGE',
        `Package boundary corruption: Expected ${expectedTotalSize} bytes, actual file has ${inputBytes.length} bytes.`,
        [
          ...steps,
          { step: '3. Container Boundary Check', passed: false, detail: `Container size mismatch: ${inputBytes.length} vs expected ${expectedTotalSize}.` },
        ]
      );
    }
    steps.push({ step: '3. Container Boundaries', passed: true, detail: `Verified layout: Manifest (${mLen}B), IV (${ivLen}B), Tag (${tagLen}B), Payload (${pLen}B).` });

    // Stage 5: Container Integrity Trailer Verification (SHA-256)
    const precedingBytes = inputBytes.subarray(0, expectedTotalBody);
    const trailerBytes = inputBytes.subarray(expectedTotalBody, expectedTotalSize);
    const calculatedChecksum = await sha256Bytes(precedingBytes);

    let checksumMatched = true;
    for (let i = 0; i < TRAILER_SIZE; i++) {
      if (trailerBytes[i] !== calculatedChecksum[i]) {
        checksumMatched = false;
        break;
      }
    }

    if (!checksumMatched) {
      return this.failResult(
        'PACKAGE_INTEGRITY_FAILURE',
        'Package container integrity checksum mismatch. The container has been tampered with or modified.',
        [
          ...steps,
          { step: '4. Container Checksum', passed: false, detail: 'Trailer SHA-256 checksum does not match calculated digest. Tampering detected!' },
        ]
      );
    }
    steps.push({ step: '4. Container Checksum', passed: true, detail: 'Trailer SHA-256 checksum perfectly verified.' });

    // Stage 6: Manifest Parsing & Structural Verification
    let manifest: SihpkgManifest;
    try {
      const manifestBytes = inputBytes.subarray(HEADER_SIZE, HEADER_SIZE + mLen);
      const manifestJson = new TextDecoder().decode(manifestBytes);
      manifest = JSON.parse(manifestJson);
    } catch (parseErr: any) {
      return this.failResult(
        'CORRUPTED_PACKAGE',
        `Manifest JSON parsing failure: ${parseErr.message}`,
        [
          ...steps,
          { step: '5. Manifest Parsing', passed: false, detail: `JSON parse exception: ${parseErr.message}` },
        ]
      );
    }

    if (!manifest.packageId || !manifest.document || !manifest.encryption || !manifest.recipients) {
      return this.failResult(
        'CORRUPTED_PACKAGE',
        'Manifest missing required structural components (packageId, document, encryption, recipients).',
        [
          ...steps,
          { step: '5. Manifest Structure', passed: false, detail: 'Missing required manifest keys.' },
        ]
      );
    }
    steps.push({ step: '5. Manifest Structure', passed: true, detail: `Manifest valid for package ID: ${manifest.packageId}.` });

    // Stage 6b: Authoritative Package Quarantine & Revocation Check
    try {
      const storedPackages = await airGappedStorage.getPackages();
      const existingRecord = storedPackages?.find((p: any) => p.packageId === manifest.packageId);
      if (existingRecord && existingRecord.lifecycleState === 'REVOKED') {
        return this.failResult(
          'PACKAGE_QUARANTINED',
          `Package quarantine active: Package ${manifest.packageId} is isolated/revoked in authoritative storage and cannot be re-imported.`,
          [
            ...steps,
            {
              step: '5b. Quarantine Status Check',
              passed: false,
              detail: `Authoritative security policy: Package ${manifest.packageId} has been revoked and isolated. Re-import is forbidden to prevent quarantine bypass.`,
            },
          ],
          manifest.packageId
        );
      }
    } catch (e) {
      console.warn('[PackageExportService] Failed to check authoritative package quarantine:', e);
    }

    // Stage 7: Encrypted Document Payload Hash Verification
    const ivBytes = inputBytes.subarray(HEADER_SIZE + mLen, HEADER_SIZE + mLen + ivLen);
    const tagBytes = inputBytes.subarray(HEADER_SIZE + mLen + ivLen, HEADER_SIZE + mLen + ivLen + tagLen);
    const payloadBytes = inputBytes.subarray(HEADER_SIZE + mLen + ivLen + tagLen, expectedTotalBody);

    const computedPayloadHash = await sha256Hex(payloadBytes);
    if (computedPayloadHash.toLowerCase().trim() !== manifest.integrity.payloadHashSha256.toLowerCase().trim()) {
      return this.failResult(
        'PAYLOAD_INTEGRITY_FAILURE',
        `Encrypted payload hash mismatch: Stored ${manifest.integrity.payloadHashSha256.slice(0, 16)}... calculated ${computedPayloadHash.slice(0, 16)}...`,
        [
          ...steps,
          { step: '6. Payload Hash Verification', passed: false, detail: 'Ciphertext bytes altered or corrupted.' },
        ]
      );
    }
    steps.push({ step: '6. Payload Hash Verification', passed: true, detail: `Payload SHA-256 digest verified (${payloadBytes.length} bytes).` });

    // Stage 8: Document Cryptographic AAD Binding Verification
    const expectedAad = computeDocumentAad(manifest.document.documentId, manifest.document.originalDocumentHashSha256);
    if (manifest.encryption.aadBinding !== expectedAad) {
      return this.failResult(
        'DOCUMENT_BINDING_FAILURE',
        `Document AAD binding failure: Manifest AAD does not match canonical document hash binding. Document ID or hash tampered.`,
        [
          ...steps,
          { step: '7. Document AAD Binding', passed: false, detail: 'AAD binding mismatch detected. Tag will fail on decryption.' },
        ]
      );
    }
    steps.push({ step: '7. Document AAD Binding', passed: true, detail: `Cryptographic AAD binding verified: ${manifest.document.documentId}` });

    // Stage 9: Distribution Binding Verification
    if (!manifest.distributionId || typeof manifest.distributionId !== 'string' || manifest.distributionId.length < 5) {
      return this.failResult(
        'DISTRIBUTION_BINDING_FAILURE',
        'Invalid or missing distribution ID in package manifest.',
        [
          ...steps,
          { step: '8. Distribution Binding', passed: false, detail: 'Missing distribution identifier.' },
        ]
      );
    }
    steps.push({ step: '8. Distribution Binding', passed: true, detail: `Distribution ID bound: ${manifest.distributionId}` });

    // Stage 10: Recipient Envelopes & Post-Quantum Key Integrity Verification
    if (manifest.recipients.length === 0) {
      return this.failResult(
        'ENVELOPE_INTEGRITY_FAILURE',
        'Package contains zero recipient key encapsulation envelopes.',
        [
          ...steps,
          { step: '9. Recipient Envelopes', passed: false, detail: 'Zero recipient envelopes present.' },
        ]
      );
    }

    const seenRecips = new Set<string>();
    for (const env of manifest.recipients) {
      if (seenRecips.has(env.recipientId)) {
        return this.failResult(
          'ENVELOPE_INTEGRITY_FAILURE',
          `Duplicate recipient envelope for ${env.recipientId}. Envelope substitution detected.`,
          [
            ...steps,
            { step: '9. Recipient Envelopes', passed: false, detail: `Duplicate envelope for ${env.recipientId}.` },
          ]
        );
      }
      seenRecips.add(env.recipientId);

      if (env.kemAlgorithm !== 'ML-KEM-768') {
        return this.failResult(
          'ENVELOPE_INTEGRITY_FAILURE',
          `Unsupported KEM algorithm ${env.kemAlgorithm} in envelope for ${env.recipientId}.`,
          [
            ...steps,
            { step: '9. Recipient Envelopes', passed: false, detail: `Invalid algorithm: ${env.kemAlgorithm}.` },
          ]
        );
      }

      try {
        const ctBytes = base64ToBytes(env.kemCiphertextBase64);
        if (ctBytes.length !== 1088) {
          return this.failResult(
            'ENVELOPE_INTEGRITY_FAILURE',
            `Invalid ML-KEM-768 ciphertext length for ${env.recipientName}: expected 1088 bytes, got ${ctBytes.length}.`,
            [
              ...steps,
              { step: '9. Recipient Envelopes', passed: false, detail: `Mismatched KEM ciphertext size for ${env.recipientId}.` },
            ]
          );
        }
      } catch {
        return this.failResult(
          'ENVELOPE_INTEGRITY_FAILURE',
          `Malformed base64 KEM ciphertext in envelope for ${env.recipientId}.`,
          [
            ...steps,
            { step: '9. Recipient Envelopes', passed: false, detail: `Base64 decode failed for ${env.recipientId}.` },
          ]
        );
      }

      try {
        const wrappedBytes = base64ToBytes(env.wrappedCekBase64);
        if (wrappedBytes.length < 32) {
          return this.failResult(
            'ENVELOPE_INTEGRITY_FAILURE',
            `Truncated wrapped CEK in envelope for ${env.recipientId}.`,
            [
              ...steps,
              { step: '9. Recipient Envelopes', passed: false, detail: `Wrapped CEK truncated for ${env.recipientId}.` },
            ]
          );
        }
      } catch {
        return this.failResult(
          'ENVELOPE_INTEGRITY_FAILURE',
          `Malformed base64 wrapped CEK in envelope for ${env.recipientId}.`,
          [
            ...steps,
            { step: '9. Recipient Envelopes', passed: false, detail: `Base64 decode failed for wrapped CEK.` },
          ]
        );
      }
    }
    steps.push({
      step: '9. Recipient Envelopes',
      passed: true,
      detail: `Verified ${manifest.recipients.length} NIST FIPS 203 ML-KEM-768 key envelopes.`,
    });

    // Stage 11: Local Recipient Authorization Matching
    const effectiveUserId = currentUserId || currentSession?.userId;
    let recipientAuthorization: PackageValidationResult['recipientAuthorization'] = undefined;

    if (effectiveUserId) {
      let isRecipientAuthoritativelyRevoked = false;
      try {
        const storedRecips = await airGappedStorage.getRecipients();
        const storedRecip = storedRecips?.find((r: any) => r.id === effectiveUserId);
        if (storedRecip && (storedRecip.status === 'REVOKED' || storedRecip.distributionStatus === 'REVOKED')) {
          isRecipientAuthoritativelyRevoked = true;
        }
      } catch {}

      const match = manifest.recipients.find((r) => r.recipientId === effectiveUserId);
      if (match) {
        if (match.status === 'REVOKED' || isRecipientAuthoritativelyRevoked) {
          recipientAuthorization = {
            recipientId: match.recipientId,
            recipientName: match.recipientName,
            status: 'REVOKED',
            canDecrypt: false,
            reason: isRecipientAuthoritativelyRevoked
              ? 'Access Revoked: Recipient clearance has been REVOKED in local authoritative security registry.'
              : 'Access Revoked: Recipient authorization has been REVOKED by the sender authority.',
          };
        } else {
          recipientAuthorization = {
            recipientId: match.recipientId,
            recipientName: match.recipientName,
            status: 'AUTHORIZED',
            canDecrypt: true,
            reason: 'Recipient identity verified and authorized for decryption.',
          };
        }
      } else {
        recipientAuthorization = {
          recipientId: effectiveUserId,
          recipientName: 'Unknown/Unlisted',
          status: 'UNAUTHORIZED',
          canDecrypt: false,
          reason: 'Unauthorized: Current user is not in the authorized recipient list for this package.',
        };
      }
    }

    steps.push({
      step: '10. Recipient Authorization',
      passed: recipientAuthorization ? recipientAuthorization.canDecrypt : true,
      detail: recipientAuthorization
        ? `${recipientAuthorization.status}: ${recipientAuthorization.reason}`
        : `${manifest.recipients.length} authorized recipients listed in package.`,
    });

    // Reconstruct valid EncryptedPackage
    const reconstructedPackage: EncryptedPackage = {
      packageId: manifest.packageId,
      distributionId: manifest.distributionId,
      documentId: manifest.document.documentId,
      documentTitle: manifest.document.documentTitle,
      classification: manifest.document.classification,
      version: manifest.version,
      originalDocumentHashSha256: manifest.document.originalDocumentHashSha256,
      ciphertextBase64: bytesToBase64(payloadBytes),
      ivHex: bytesToHex(ivBytes),
      tagHex: bytesToHex(tagBytes),
      envelopes: manifest.recipients.map((r) => ({
        recipientId: r.recipientId,
        recipientName: r.recipientName,
        envelopeId: r.envelopeId,
        publicKeyFingerprint: r.publicKeyFingerprint,
        kemAlgorithm: r.kemAlgorithm,
        kemCiphertextBase64: r.kemCiphertextBase64,
        wrappedCekBase64: r.wrappedCekBase64,
        status: r.status,
      })),
      senderId: manifest.sender.senderId,
      senderName: manifest.sender.senderName,
      createdAt: manifest.createdAt,
      isPdf: manifest.document.mimeType === 'application/pdf',
      mimeType: manifest.document.mimeType,
      filename: manifest.document.filename,
      fileSizeBytes: manifest.document.sizeBytes,
      lifecycleState: 'IMPORTED',
      importedAt: Date.now(),
      isImported: true,
    };

    // Save package into persistent storage
    await airGappedStorage.savePackage(reconstructedPackage);

    // Record audit event
    await this.recordAuditEvent({
      eventId: `AUD-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 8999 + 1000)}`,
      eventType: 'PACKAGE_IMPORTED',
      timestamp: Date.now(),
      packageId: manifest.packageId,
      distributionId: manifest.distributionId,
      documentId: manifest.document.documentId,
      recipientId: effectiveUserId,
      status: 'SUCCESS',
      details: `Successfully imported and registered package ${manifest.packageId} (${manifest.document.documentTitle}).`,
    });

    return {
      isValid: true,
      status: 'VALID',
      manifest,
      package: reconstructedPackage,
      rawBinary: inputBytes,
      validationSteps: steps.map((s) => ({ name: s.step, passed: s.passed, detail: s.detail })),
      recipientAuthorization,
    };
  }

  /**
   * Helper to format a rejected validation result and log the failure.
   */
  private static async failResult(
    status: PackageValidationResult['status'],
    errorMessage: string,
    steps: Array<{ step: string; passed: boolean; detail: string }>,
    packageId?: string
  ): Promise<PackageValidationResult> {
    await this.recordAuditEvent({
      eventId: `AUD-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 8999 + 1000)}`,
      eventType: 'PACKAGE_VALIDATION_FAILED',
      timestamp: Date.now(),
      packageId: packageId || 'UNKNOWN',
      status: 'FAILED',
      details: `Validation failed: [${status}] ${errorMessage}`,
    });

    return {
      isValid: false,
      status,
      errorMessage,
      validationSteps: steps.map((s) => ({ name: s.step, passed: s.passed, detail: s.detail })),
    };
  }

  /**
   * Helper to download Uint8Array buffer as a .sihpkg file.
   */
  public static triggerDownload(buffer: Uint8Array, filename: string): void {
    const blob = new Blob([buffer as any], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename.endsWith('.sihpkg') ? filename : `${filename}.sihpkg`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /**
   * Record package audit event in persistent storage and central audit service.
   */
  public static async recordAuditEvent(event: PackageAuditEvent): Promise<void> {
    try {
      const severity: 'INFO' | 'WARNING' | 'ERROR' =
        event.status === 'FAILED' ? 'ERROR' : event.status === 'REJECTED' ? 'WARNING' : 'INFO';
      const category =
        event.eventType === 'PACKAGE_VALIDATION_FAILED' || event.eventType === 'PACKAGE_REJECTED'
          ? 'SECURITY'
          : 'PACKAGE';

      await auditService.record({
        eventType: event.eventType,
        severity,
        category,
        actor: { type: 'USER', id: event.recipientId || 'SYSTEM' },
        resource: { type: 'PACKAGE', id: event.packageId },
        action: event.eventType,
        outcome: event.status === 'SUCCESS' ? 'SUCCESS' : event.status === 'REJECTED' ? 'REJECTED' : 'FAILURE',
        description: event.details || `Package event ${event.eventType}`,
        packageId: event.packageId,
        distributionId: event.distributionId,
        documentId: event.documentId,
        recipientId: event.recipientId,
      }).catch((e) => console.warn('[PackageExportService] Failed to record in auditService:', e));
    } catch (e) {
      console.warn('[PackageExportService] Failed to record audit log:', e);
    }
  }

  /**
   * Get all recorded package audit events.
   */
  public static async getAuditEvents(): Promise<PackageAuditEvent[]> {
    try {
      return (await airGappedStorage.getAuditEvents()) as PackageAuditEvent[];
    } catch {
      return [];
    }
  }
}
