import './setup.ts';
import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  signWithMlDsa65,
  verifyMlDsa65,
} from '../src/crypto/pqc.ts';

describe('TEST GROUP 2: ML-DSA-65 (NIST FIPS 204)', () => {
  it('2.1 Key Generation: generates valid ML-DSA-65 key lengths', () => {
    const rawKeys = ml_dsa65.keygen();
    // NIST FIPS 204 ML-DSA-65 specifies:
    // Public Key length = 1952 bytes
    // Secret Key length = 4032 bytes
    assert.strictEqual(rawKeys.publicKey.length, 1952, 'ML-DSA-65 public key must be exactly 1952 bytes');
    assert.strictEqual(rawKeys.secretKey.length, 4032, 'ML-DSA-65 secret key must be exactly 4032 bytes');
  });

  it('2.2 Valid Signing & Verification: creates 3309-byte signature and verifies correctly', () => {
    const keys = ml_dsa65.keygen();
    const message = new TextEncoder().encode('DECRYPTION-EVENT-SESSION-ALPHA-2026');

    const signature = signWithMlDsa65(message, keys.secretKey);
    // NIST FIPS 204 ML-DSA-65 signature length = 3309 bytes
    assert.strictEqual(signature.length, 3309, 'ML-DSA-65 signature must be 3309 bytes');

    const isValid = verifyMlDsa65(signature, message, keys.publicKey);
    assert.strictEqual(isValid, true, 'Genuine signature must verify successfully');
  });

  it('2.3 Modified Message Rejection: tampering with signed payload fails verification', () => {
    const keys = ml_dsa65.keygen();
    const originalMessage = new TextEncoder().encode('DECRYPTION-EVENT-USER-ALICE');
    const tamperedMessage = new TextEncoder().encode('DECRYPTION-EVENT-USER-BOB');

    const signature = signWithMlDsa65(originalMessage, keys.secretKey);

    const isValid = verifyMlDsa65(signature, tamperedMessage, keys.publicKey);
    assert.strictEqual(isValid, false, 'Signature verification must fail on modified message');
  });

  it('2.4 Modified Signature Rejection: bit-flipped signature fails verification', () => {
    const keys = ml_dsa65.keygen();
    const message = new TextEncoder().encode('CRITICAL-INFRASTRUCTURE-PROVENANCE-RECORD');

    const signature = signWithMlDsa65(message, keys.secretKey);
    const corruptedSignature = new Uint8Array(signature);
    corruptedSignature[24] ^= 0x01; // flip 1 bit

    const isValid = verifyMlDsa65(corruptedSignature, message, keys.publicKey);
    assert.strictEqual(isValid, false, 'Bit-flipped signature must fail verification');
  });

  it('2.5 Wrong Public Key Rejection: verifying with another recipient public key fails', () => {
    const aliceKeys = ml_dsa65.keygen();
    const bobKeys = ml_dsa65.keygen();
    const message = new TextEncoder().encode('ALICE-EXCLUSIVE-DOCUMENT-ACCESS');

    // Alice signs the message
    const aliceSignature = signWithMlDsa65(message, aliceKeys.secretKey);

    // Verify using Bob's public key
    const isValid = verifyMlDsa65(aliceSignature, message, bobKeys.publicKey);
    assert.strictEqual(isValid, false, 'Verifying with mismatched public key must fail');
  });
});
