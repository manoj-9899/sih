import './setup';
import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import { DistributionService } from '../src/services/distributionService';
import {
  PackageExportService,
  SIHPKG_MAGIC,
  SIHPKG_VERSION,
  HEADER_SIZE,
  TRAILER_SIZE,
} from '../src/services/packageExportService';
import { sessionManager } from '../src/crypto/sessionManager';
import { SAMPLE_DOCUMENTS, initializeRecipientsAndLedger } from '../src/data/sampleData';
import { Recipient, EncryptedPackage } from '../src/types';
import { sha256Bytes, sha256Hex, base64ToBytes, bytesToBase64 } from '../src/crypto/pqc';

describe('SEC-18 to SEC-24: .SIHPKG PORTABLE ENCRYPTED PACKAGE SECURITY SUITE', () => {
  let alice: Recipient;
  let bob: Recipient;
  let charlie: Recipient;
  let testPkg: EncryptedPackage;
  const sampleDoc = SAMPLE_DOCUMENTS[0];

  before(async () => {
    const recipients = await initializeRecipientsAndLedger();
    alice = recipients[0];
    bob = recipients[1];
    charlie = recipients[2];

    // Create encrypted package with Alice and Bob as authorized recipients
    testPkg = await DistributionService.createEncryptedPackage(sampleDoc, [alice, bob]);
  });

  test('SEC-18: Package Tampering — modified manifest is detected and rejected', async () => {
    const validBinary = await PackageExportService.exportPackageToBinary(testPkg);
    assert.ok(validBinary.length > HEADER_SIZE + TRAILER_SIZE);

    // Tamper with bytes inside the manifest section (e.g. byte 30)
    const tamperedBinary = new Uint8Array(validBinary);
    tamperedBinary[30] = tamperedBinary[30] ^ 0xff; // Flip bits

    const result = await PackageExportService.validateAndImportPackage(tamperedBinary, alice.id);
    assert.strictEqual(result.isValid, false);
    assert.ok(
      result.status === 'PACKAGE_INTEGRITY_FAILURE' || result.status === 'CORRUPTED_PACKAGE',
      `Expected PACKAGE_INTEGRITY_FAILURE or CORRUPTED_PACKAGE, got ${result.status}`
    );
    assert.strictEqual(result.package, undefined);
  });

  test('SEC-19: Payload Tampering — modified encrypted payload is detected and rejected', async () => {
    const validBinary = await PackageExportService.exportPackageToBinary(testPkg);
    const tamperedBinary = new Uint8Array(validBinary);

    // Modify a byte in the payload area (near the end, but before the 32-byte trailer)
    const payloadByteIndex = tamperedBinary.length - TRAILER_SIZE - 5;
    tamperedBinary[payloadByteIndex] = tamperedBinary[payloadByteIndex] ^ 0xaa;

    const result = await PackageExportService.validateAndImportPackage(tamperedBinary, alice.id);
    assert.strictEqual(result.isValid, false);
    assert.ok(
      result.status === 'PACKAGE_INTEGRITY_FAILURE' || result.status === 'PAYLOAD_INTEGRITY_FAILURE',
      `Expected PACKAGE_INTEGRITY_FAILURE or PAYLOAD_INTEGRITY_FAILURE, got ${result.status}`
    );
  });

  test('SEC-20: Envelope Substitution — duplicate or substituted envelope is detected and rejected', async () => {
    // Construct a package with duplicate recipient envelope (attempting substitution)
    const substitutedPkg: EncryptedPackage = {
      ...testPkg,
      packageId: 'PKG-SUBST-001',
      envelopes: [
        testPkg.envelopes[0],
        { ...testPkg.envelopes[0], envelopeId: 'ENV-SUBST-01' }, // Duplicate Alice envelope for second slot
      ],
    };

    const substitutedBinary = await PackageExportService.exportPackageToBinary(substitutedPkg);
    const result = await PackageExportService.validateAndImportPackage(substitutedBinary, alice.id);

    assert.strictEqual(result.isValid, false);
    assert.strictEqual(result.status, 'ENVELOPE_INTEGRITY_FAILURE');
  });

  test('SEC-21: Unauthorized Import — unauthorized recipient imports valid package but cannot decrypt', async () => {
    // Valid package was created for Alice and Bob, NOT Charlie
    const validBinary = await PackageExportService.exportPackageToBinary(testPkg);

    // Charlie imports package
    const importResult = await PackageExportService.validateAndImportPackage(validBinary, charlie.id);

    // Package structure is valid, but Charlie is unauthorized
    assert.strictEqual(importResult.isValid, true);
    assert.strictEqual(importResult.status, 'VALID');
    assert.ok(importResult.package);
    assert.ok(importResult.recipientAuthorization);
    assert.strictEqual(importResult.recipientAuthorization.status, 'UNAUTHORIZED');
    assert.strictEqual(importResult.recipientAuthorization.canDecrypt, false);

    // Charlie attempts decryption with Charlie session -> must fail
    await sessionManager.createSession(charlie, 'CharlieChen2026!');
    const charlieSession = sessionManager.getActiveSession();

    await assert.rejects(
      async () => {
        await DistributionService.executeRecipientDecryption(importResult.package!, charlie, charlieSession);
      },
      (err: any) => err.message.includes('No ML-KEM-768 envelope found') || err.message.includes('Hardware Keystore Error') || err.message.includes('Recipient')
    );
  });

  test('SEC-22: Revoked Recipient — revoked recipient is rejected from decryption', async () => {
    // Construct package where Bob has status: 'REVOKED'
    const revokedPkg: EncryptedPackage = {
      ...testPkg,
      packageId: 'PKG-REVOKED-001',
      envelopes: [
        testPkg.envelopes[0],
        { ...testPkg.envelopes[1], status: 'REVOKED' },
      ],
    };

    const binary = await PackageExportService.exportPackageToBinary(revokedPkg);
    const importResult = await PackageExportService.validateAndImportPackage(binary, bob.id);

    assert.strictEqual(importResult.isValid, true);
    assert.ok(importResult.recipientAuthorization);
    assert.strictEqual(importResult.recipientAuthorization.status, 'REVOKED');
    assert.strictEqual(importResult.recipientAuthorization.canDecrypt, false);
  });

  test('SEC-23: Corrupted Package — truncated buffer or wrong magic/version is rejected without crashing', async () => {
    // 1. Truncated package
    const truncated = new Uint8Array([0x53, 0x49, 0x48, 0x50]); // 4 bytes
    const r1 = await PackageExportService.validateAndImportPackage(truncated);
    assert.strictEqual(r1.isValid, false);
    assert.strictEqual(r1.status, 'CORRUPTED_PACKAGE');

    // 2. Corrupted Magic
    const badMagic = new Uint8Array(64);
    badMagic.set([0x4e, 0x4f, 0x54, 0x53, 0x49, 0x48, 0x00, 0x00], 0);
    const r2 = await PackageExportService.validateAndImportPackage(badMagic);
    assert.strictEqual(r2.isValid, false);
    assert.strictEqual(r2.status, 'CORRUPTED_PACKAGE');

    // 3. Unsupported Version (v99)
    const validBinary = await PackageExportService.exportPackageToBinary(testPkg);
    const badVersionBinary = new Uint8Array(validBinary);
    const view = new DataView(badVersionBinary.buffer, badVersionBinary.byteOffset, badVersionBinary.byteLength);
    view.setUint16(8, 99, false); // Version 99

    // Recompute trailer to isolate version check
    const preceding = badVersionBinary.subarray(0, badVersionBinary.length - TRAILER_SIZE);
    const newTrailer = await sha256Bytes(preceding);
    badVersionBinary.set(newTrailer, badVersionBinary.length - TRAILER_SIZE);

    const r3 = await PackageExportService.validateAndImportPackage(badVersionBinary);
    assert.strictEqual(r3.isValid, false);
    assert.strictEqual(r3.status, 'UNSUPPORTED_VERSION');
    assert.ok(r3.errorMessage?.includes('Unsupported package version'));
  });

  test('SEC-24: Valid Package — full round-trip export, import, decrypt, watermark, and provenance', async () => {
    // 1. Export package to .sihpkg binary
    const binary = await PackageExportService.exportPackageToBinary(testPkg);
    assert.ok(binary.length > 500);

    // 2. Alice imports package
    const importResult = await PackageExportService.validateAndImportPackage(binary, alice.id);
    assert.strictEqual(importResult.isValid, true);
    assert.strictEqual(importResult.status, 'VALID');
    assert.ok(importResult.package);
    assert.ok(importResult.recipientAuthorization?.canDecrypt);

    // 3. Authenticate Alice session
    await sessionManager.createSession(alice, 'AliceVance2026!');
    const aliceSession = sessionManager.getActiveSession();
    assert.ok(aliceSession);

    // 4. Decrypt imported package
    const decryptResult = await DistributionService.executeRecipientDecryption(
      importResult.package!,
      alice,
      aliceSession
    );

    // 5. Verify watermark and provenance event creation
    assert.ok(decryptResult.decryptionEvent);
    assert.strictEqual(decryptResult.decryptionEvent.recipientId, alice.id);
    assert.ok(decryptResult.watermarkPayload);
    assert.strictEqual(decryptResult.watermarkPayload.recipientId, alice.id);
    assert.ok(decryptResult.watermarkedText.length > 0);
    assert.ok(decryptResult.blockHeight >= 1);

    // 6. Verify audit logs recorded PACKAGE_EXPORTED, PACKAGE_IMPORTED, and PACKAGE_DECRYPTED
    const audits = await PackageExportService.getAuditEvents();
    const types = audits.map((a) => a.eventType);
    assert.ok(types.includes('PACKAGE_EXPORTED'));
    assert.ok(types.includes('PACKAGE_IMPORTED'));
    assert.ok(types.includes('PACKAGE_DECRYPTED'));
  });
});
