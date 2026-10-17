/**
 * AEGIS-PQC Offline Signed Receipt (.sihrcpt) Service.
 * 
 * Implements:
 * 1. Generation of verifiable offline decryption receipts signed with ML-DSA-65.
 * 2. Canonical serialization (.sihrcpt v1) with deterministic JSON normalization.
 * 3. Offline verification of receipts against enrolled post-quantum public keys
 *    and local air-gapped provenance ledger blocks.
 * 
 * Cryptographic Invariants & Trust Model:
 * - Verification strictly binds signatures to registered recipient identities in the
 *   enclave directory (`airGappedStorage.getRecipients()`). Embedded public keys are
 *   never trusted blindly.
 * - Receipts NEVER contain original PDF bytes, decrypted plaintext, or encryption keys.
 * - Signatures use NIST FIPS 204 (ML-DSA-65) over canonical deterministic JSON.
 * - Verification distinguishes mathematical signature validity, signer identity binding,
 *   and immutable ledger transaction corroboration.
 */

import {
  SignedOfflineReceipt,
  ReceiptPayload,
  ReceiptVerificationResult,
  ReceiptAssuranceTier,
  SIHRCPT_MAGIC,
  SIHRCPT_VERSION,
  EncryptedPackage,
  Recipient,
  DecryptionEvent,
  WatermarkPayload,
  DocumentAssignment,
} from '../types';
import {
  signWithMlDsa65,
  verifyMlDsa65,
  canonicalizeJson,
  bytesToBase64,
  base64ToBytes,
  hexToBytes,
  bytesToHex,
} from '../crypto/pqc';
import { sessionManager, AuthenticatedSession } from '../crypto/sessionManager';
import { airGappedStorage } from '../storage/airGappedStorage';
import { airGappedLedger } from '../ledger/dlt';
import { auditService } from './auditService';

export interface GenerateReceiptParams {
  pkg: EncryptedPackage;
  recipient: Recipient;
  decryptionEvent: DecryptionEvent;
  watermarkPayload: WatermarkPayload;
  blockHeight: number;
  blockHash?: string;
  assignment?: DocumentAssignment | null;
  session?: AuthenticatedSession | null;
}

export interface VerifyReceiptOptions {
  trustedRecipients?: Recipient[];
}

export class ReceiptService {
  /**
   * Deterministically canonicalizes a receipt payload for signing or verification.
   * Excludes signature fields to ensure idempotent payload hashing.
   * Strictly normalizes types and properties to prevent prototype or type confusion attacks.
   */
  public static canonicalizeReceipt(payload: ReceiptPayload): string {
    return canonicalizeJson({
      magic: String(payload.magic || ''),
      version: Number(payload.version || 0),
      receiptId: String(payload.receiptId || ''),
      assignmentId: String(payload.assignmentId || ''),
      distributionId: String(payload.distributionId || ''),
      packageId: String(payload.packageId || ''),
      documentId: String(payload.documentId || ''),
      documentTitle: String(payload.documentTitle || ''),
      classification: String(payload.classification || ''),
      recipientId: String(payload.recipientId || ''),
      recipientName: String(payload.recipientName || ''),
      recipientFingerprint: String(payload.recipientFingerprint || ''),
      decryptionTimestamp: Number(payload.decryptionTimestamp || 0),
      decryptionEventId: String(payload.decryptionEventId || ''),
      blockHeight: Number(payload.blockHeight ?? 0),
      blockHash: String(payload.blockHash || ''),
      watermarkId: String(payload.watermarkId || ''),
      watermarkCommitment: String(payload.watermarkCommitment || ''),
      createdAt: Number(payload.createdAt || 0),
      clientMetadata: {
        terminalId: String(payload.clientMetadata?.terminalId || ''),
        runtimeSecurity: String(payload.clientMetadata?.runtimeSecurity || ''),
      },
    });
  }

  /**
   * Generates a signed offline receipt (.sihrcpt) for a completed decryption event.
   * Requires an active authenticated session with unlocked ML-DSA-65 private key.
   */
  public static async generateReceipt(
    params: GenerateReceiptParams
  ): Promise<SignedOfflineReceipt> {
    const { pkg, recipient, decryptionEvent, watermarkPayload, blockHeight, assignment } = params;
    const session = params.session || sessionManager.getActiveSession();

    if (!session || session.status !== 'ACTIVE' || !session.unlockedKeys?.dsaSecretKey) {
      throw new Error('AuthenticationRequired: Generating a signed receipt requires an active authenticated session with unlocked signing keys.');
    }

    if (session.userId !== recipient.id) {
      throw new Error(`SessionMismatch: Active session belongs to "${session.userId}", cannot sign receipt as "${recipient.id}".`);
    }

    // Resolve block hash from ledger if not provided
    let blockHash = params.blockHash;
    if (!blockHash) {
      const block = await airGappedLedger.getBlock(blockHeight);
      blockHash = block?.blockHash || decryptionEvent.txHash || '';
    }

    const now = Date.now();
    const receiptId = `RCPT-${now.toString(36).toUpperCase()}-${Math.floor(Math.random() * 8999 + 1000)}`;

    const distId = assignment?.distributionId || pkg.distributionId || `DIST-${pkg.packageId}`;
    const asgnId = assignment?.assignmentId || `ASGN-${distId}-${recipient.id}`;

    const payload: ReceiptPayload = {
      magic: SIHRCPT_MAGIC,
      version: SIHRCPT_VERSION,
      receiptId,
      assignmentId: asgnId,
      distributionId: distId,
      packageId: pkg.packageId,
      documentId: pkg.documentId,
      documentTitle: pkg.documentTitle,
      classification: pkg.classification,
      recipientId: recipient.id,
      recipientName: recipient.name,
      recipientFingerprint: recipient.keys.keyFingerprint,
      decryptionTimestamp: decryptionEvent.timestampEpochMs || now,
      decryptionEventId: decryptionEvent.eventId,
      blockHeight,
      blockHash,
      watermarkId: watermarkPayload.watermarkId,
      watermarkCommitment: watermarkPayload.watermarkCommitment || decryptionEvent.watermarkCommitment || '',
      createdAt: now,
      clientMetadata: {
        terminalId: `SECURE-WS-${recipient.avatarInitials}-409`,
        runtimeSecurity: 'NIST-FIPS-140-3-ISOLATED',
      },
    };

    // 1. Canonicalize payload
    const canonicalPayloadString = this.canonicalizeReceipt(payload);

    // 2. Sign canonical payload using recipient's ML-DSA-65 secret key (NIST FIPS 204)
    const signatureBytes = signWithMlDsa65(
      new TextEncoder().encode(canonicalPayloadString),
      session.unlockedKeys.dsaSecretKey
    );

    const signedReceipt: SignedOfflineReceipt = {
      ...payload,
      signatureAlgorithm: 'ML-DSA-65',
      signatureBase64: bytesToBase64(signatureBytes),
      signerPublicKeyHex: recipient.keys.dsaPublicKeyHex,
    };

    // Record audit event
    await auditService.record({
      eventType: 'PROVENANCE_EVENT_SIGNED',
      severity: 'INFO',
      category: 'PROVENANCE',
      actor: { type: 'USER', id: recipient.id, displayName: recipient.name },
      resource: { type: 'PACKAGE', id: pkg.packageId },
      action: 'SIGN_PROVENANCE',
      outcome: 'SUCCESS',
      description: `Signed offline decryption receipt ${receiptId} generated with ML-DSA-65 for document "${pkg.documentTitle}".`,
      documentId: pkg.documentId,
      packageId: pkg.packageId,
      recipientId: recipient.id,
      metadata: {
        receiptId,
        blockHeight,
        eventId: decryptionEvent.eventId,
        watermarkId: watermarkPayload.watermarkId,
      },
    }).catch((e) => console.warn('[ReceiptService] Audit log failed:', e));

    return signedReceipt;
  }

  /**
   * Serializes a signed offline receipt into formatted JSON text suitable for .sihrcpt files.
   */
  public static serializeReceipt(receipt: SignedOfflineReceipt): string {
    return JSON.stringify(receipt, null, 2);
  }

  /**
   * Parses and validates raw receipt file content (.sihrcpt format).
   * Validates structural invariants, magic constants, versions, and numeric ranges.
   */
  public static parseReceipt(content: string | Uint8Array): SignedOfflineReceipt {
    let jsonString: string;
    if (typeof content === 'string') {
      jsonString = content;
    } else {
      jsonString = new TextDecoder('utf-8').decode(content);
    }

    let parsed: any;
    try {
      parsed = JSON.parse(jsonString);
    } catch {
      throw new Error('InvalidReceiptFormat: Receipt file is not valid JSON.');
    }

    if (!parsed || typeof parsed !== 'object') {
      throw new Error('InvalidReceiptFormat: Receipt root must be an object.');
    }

    if (parsed.magic !== SIHRCPT_MAGIC) {
      throw new Error(`InvalidReceiptFormat: Unrecognized magic header "${parsed.magic}". Expected "${SIHRCPT_MAGIC}".`);
    }

    if (parsed.version !== SIHRCPT_VERSION) {
      throw new Error(`UnsupportedReceiptVersion: Schema version ${parsed.version} is not supported. Supported version is ${SIHRCPT_VERSION}.`);
    }

    if (!parsed.receiptId || typeof parsed.receiptId !== 'string' || !parsed.receiptId.startsWith('RCPT-')) {
      throw new Error('InvalidReceiptFormat: Invalid or missing receiptId.');
    }

    if (!parsed.packageId || typeof parsed.packageId !== 'string') {
      throw new Error('InvalidReceiptFormat: Missing packageId identifier.');
    }

    if (!parsed.recipientId || typeof parsed.recipientId !== 'string') {
      throw new Error('InvalidReceiptFormat: Missing recipientId identifier.');
    }

    if (!parsed.decryptionEventId || typeof parsed.decryptionEventId !== 'string') {
      throw new Error('InvalidReceiptFormat: Missing decryptionEventId identifier.');
    }

    if (typeof parsed.blockHeight !== 'number' || !Number.isInteger(parsed.blockHeight) || parsed.blockHeight < 0) {
      throw new Error('InvalidReceiptFormat: blockHeight must be a non-negative integer.');
    }

    if (typeof parsed.decryptionTimestamp !== 'number' || parsed.decryptionTimestamp <= 0) {
      throw new Error('InvalidReceiptFormat: decryptionTimestamp must be a valid positive epoch timestamp.');
    }

    if (parsed.signatureAlgorithm !== 'ML-DSA-65') {
      throw new Error(`UnsupportedSignatureAlgorithm: Expected ML-DSA-65 signature algorithm, got "${parsed.signatureAlgorithm}".`);
    }

    if (!parsed.signatureBase64 || typeof parsed.signatureBase64 !== 'string') {
      throw new Error('InvalidReceiptFormat: Missing or invalid signatureBase64 payload.');
    }

    // Verify signature format length (ML-DSA-65 signature is strictly 3,309 bytes)
    try {
      const sigBytes = base64ToBytes(parsed.signatureBase64);
      if (sigBytes.length !== 3309) {
        throw new Error(`InvalidSignatureLength: Expected 3309 bytes for ML-DSA-65 signature, received ${sigBytes.length} bytes.`);
      }
    } catch (e: any) {
      throw new Error(`InvalidReceiptFormat: signatureBase64 is corrupt: ${e.message}`);
    }

    return parsed as SignedOfflineReceipt;
  }

  /**
   * Verifies a signed offline receipt against the recipient's post-quantum public key
   * and the air-gapped provenance ledger.
   * 
   * Trust Model:
   * 1. Identity Binding: Signer must match a known recipient in the trusted registry.
   *    Embedded public keys on the receipt are NOT blindly trusted.
   * 2. Signature Authenticity: ML-DSA-65 signature is evaluated over the canonical payload.
   * 3. Ledger Corroboration: Decryption event is cross-checked in committed blocks.
   */
  public static async verifyReceipt(
    receiptOrContent: SignedOfflineReceipt | string | Uint8Array,
    options?: VerifyReceiptOptions
  ): Promise<ReceiptVerificationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    let receipt: SignedOfflineReceipt;
    try {
      receipt = typeof receiptOrContent === 'object' && 'magic' in receiptOrContent
        ? receiptOrContent
        : this.parseReceipt(receiptOrContent);
    } catch (parseErr: any) {
      return {
        valid: false,
        signatureValid: false,
        identityBound: false,
        ledgerVerified: false,
        registeredRecipientFound: false,
        provenanceAssurance: 'INVALID_STRUCTURE',
        assuranceSummary: 'Receipt could not be parsed: ' + (parseErr.message || 'Malformed container syntax.'),
        errors: [parseErr.message || 'Failed to parse receipt file.'],
        warnings: [],
      };
    }

    // 1. Authoritative Recipient Trust Lookup
    let registeredRecipient: Recipient | undefined;
    try {
      const registry = options?.trustedRecipients || (await airGappedStorage.getRecipients()) || [];
      registeredRecipient = registry.find((r) => r.id === receipt.recipientId);
    } catch {
      warnings.push('Could not access persistent storage to query local recipient directory.');
    }

    const registeredRecipientFound = !!registeredRecipient;
    let identityBound = false;
    let signatureValid = false;

    if (!registeredRecipient) {
      errors.push(
        `UntrustedSigner: Claimed recipient "${receipt.recipientId}" is not enrolled in the local trusted recipient directory. Self-asserted signatures cannot be verified.`
      );
    } else {
      // 2. Enforce Key Binding & Detect Key Substitution Attacks
      const authoritativeDsaPubKeyHex = registeredRecipient.keys.dsaPublicKeyHex;

      if (!authoritativeDsaPubKeyHex) {
        errors.push(`MissingEnrolledKey: Registered recipient "${receipt.recipientId}" has no ML-DSA-65 public key registered.`);
      } else {
        // Detect key substitution attack if receipt claims a different public key
        if (
          receipt.signerPublicKeyHex &&
          receipt.signerPublicKeyHex.toLowerCase() !== authoritativeDsaPubKeyHex.toLowerCase()
        ) {
          errors.push(
            `KeySubstitutionDetected: Public key in receipt does not match the registered ML-DSA-65 public key for "${receipt.recipientId}". Possible forgery attempt.`
          );
        }

        // Validate key fingerprint binding
        if (
          receipt.recipientFingerprint &&
          registeredRecipient.keys.keyFingerprint &&
          receipt.recipientFingerprint !== registeredRecipient.keys.keyFingerprint
        ) {
          errors.push(
            `FingerprintMismatch: Key fingerprint "${receipt.recipientFingerprint}" does not match registered fingerprint "${registeredRecipient.keys.keyFingerprint}".`
          );
        }

        // 3. Cryptographic ML-DSA-65 Verification using Authoritative Public Key
        try {
          const canonicalPayloadString = this.canonicalizeReceipt(receipt);
          const signatureBytes = base64ToBytes(receipt.signatureBase64);
          const pubKeyBytes = hexToBytes(authoritativeDsaPubKeyHex);

          signatureValid = verifyMlDsa65(
            signatureBytes,
            new TextEncoder().encode(canonicalPayloadString),
            pubKeyBytes
          );

          if (!signatureValid) {
            errors.push('CryptographicVerificationFailed: ML-DSA-65 signature does not match canonical receipt payload.');
          } else {
            identityBound = true;
          }
        } catch (cryptoErr: any) {
          errors.push(`CryptographicEvaluationError: ${cryptoErr.message}`);
          signatureValid = false;
        }
      }
    }

    // 4. Verify Ledger Provenance Against Independent Air-Gapped Chain
    let ledgerVerified = false;
    try {
      const chain = await airGappedLedger.getChain();
      const block = chain.find((b) => b.height === receipt.blockHeight);

      if (block) {
        if (receipt.blockHash && block.blockHash !== receipt.blockHash) {
          errors.push(
            `LedgerHashMismatch: Block #${receipt.blockHeight} hash in ledger (${block.blockHash.slice(0, 16)}...) differs from receipt blockHash (${receipt.blockHash.slice(0, 16)}...).`
          );
        } else {
          // Check for transaction committing this decryption event
          const matchingTx = block.transactions.find((tx) => {
            const txAny = tx as any;
            const matchesId =
              tx.eventId === receipt.decryptionEventId ||
              tx.watermarkId === receipt.watermarkId ||
              (txAny.data && (txAny.data.eventId === receipt.decryptionEventId || txAny.data.watermarkId === receipt.watermarkId));
            const matchesRecipient = !tx.recipientId || tx.recipientId === receipt.recipientId;
            return matchesId && matchesRecipient;
          });

          if (matchingTx) {
            ledgerVerified = true;
          } else {
            ledgerVerified = false;
            warnings.push(
              `LedgerTransactionNotFound: Block #${receipt.blockHeight} exists and hash matches, but does not contain a committed transaction for decryption event "${receipt.decryptionEventId}".`
            );
          }
        }
      } else {
        ledgerVerified = false;
        warnings.push(
          `LedgerBlockNotFound: Ledger block #${receipt.blockHeight} not found in current local chain (chain height: ${chain.length - 1}). Receipt was generated in another enclave or ledger was pruned.`
        );
      }
    } catch (ledgerErr: any) {
      warnings.push(`Ledger cross-check skipped: ${ledgerErr.message}`);
    }

    const valid = signatureValid && identityBound && errors.length === 0;

    // 5. Determine Clear Assurance Tier & Precise Summary
    let provenanceAssurance: ReceiptAssuranceTier;
    let assuranceSummary: string;

    if (valid && ledgerVerified) {
      provenanceAssurance = 'AUTHENTIC_AND_LEDGER_CONFIRMED';
      assuranceSummary = `Authentic ML-DSA-65 post-quantum signature bound to enrolled recipient ${registeredRecipient?.name || receipt.recipientId}, and corroborated by committed ledger Block #${receipt.blockHeight}.`;
    } else if (valid && !ledgerVerified) {
      provenanceAssurance = 'SIGNATURE_VALID_UNCONFIRMED_LEDGER';
      assuranceSummary = `Authentic ML-DSA-65 signature bound to enrolled recipient ${registeredRecipient?.name || receipt.recipientId}, but event transaction was not corroborated by the local ledger.`;
    } else if (!registeredRecipientFound) {
      provenanceAssurance = 'UNTRUSTED_OR_TAMPERED';
      assuranceSummary = 'Verification failed: Signer is not enrolled in the local trusted identity registry.';
    } else {
      provenanceAssurance = 'UNTRUSTED_OR_TAMPERED';
      assuranceSummary = 'Verification failed: Receipt signature is invalid or payload has been tampered with.';
    }

    return {
      valid,
      receipt,
      signatureValid,
      identityBound,
      ledgerVerified,
      registeredRecipientFound,
      provenanceAssurance,
      assuranceSummary,
      signerRecipient: registeredRecipient
        ? {
            id: registeredRecipient.id,
            name: registeredRecipient.name,
            role: registeredRecipient.role,
            clearanceLevel: registeredRecipient.clearanceLevel,
            avatarInitials: registeredRecipient.avatarInitials,
          }
        : undefined,
      errors,
      warnings,
    };
  }

  /**
   * Helper to trigger a browser file download of a .sihrcpt receipt.
   */
  public static triggerReceiptDownload(receipt: SignedOfflineReceipt, filenameOverride?: string): void {
    const jsonString = this.serializeReceipt(receipt);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;

    const baseTitle = receipt.documentTitle.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_-]/g, '');
    const defaultFilename = `${baseTitle}_Receipt_${receipt.receiptId}.sihrcpt`;
    a.download = filenameOverride || defaultFilename;
    a.click();
    URL.revokeObjectURL(url);
  }
}
