import './setup.ts';
import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  encryptDocumentContent,
  decryptDocumentContent,
} from '../src/crypto/pqc.ts';

describe('TEST GROUP 3: AES-256-GCM Bulk Symmetric Cipher', () => {
  it('3.1 Encryption & Decryption: roundtrips plaintext cleanly', async () => {
    const rawPlaintext = 'TOP SECRET CLASSIFIED DIRECTIVE 2026 - QUANTUM TRANSITION PROTOCOL';
    const plaintextBytes = new TextEncoder().encode(rawPlaintext);

    const { cekRaw, ciphertext, iv, tag } = await encryptDocumentContent(plaintextBytes);

    assert.strictEqual(cekRaw.length, 32, 'Content encryption key must be 32 bytes (AES-256)');
    assert.strictEqual(iv.length, 12, 'IV must be 12 bytes (96 bits)');
    assert.strictEqual(tag.length, 16, 'Authentication tag must be 16 bytes (128 bits)');

    const decryptedBytes = await decryptDocumentContent(ciphertext, tag, iv, cekRaw);
    const recoveredString = new TextDecoder().decode(decryptedBytes);

    assert.strictEqual(recoveredString, rawPlaintext, 'Decrypted text must match original plaintext');
  });

  it('3.2 Modified Ciphertext Rejection: bit-flipped ciphertext fails GCM auth tag check', async () => {
    const plaintextBytes = new TextEncoder().encode('ATTACK-TEST-TAMPER-TARGET');
    const { cekRaw, ciphertext, iv, tag } = await encryptDocumentContent(plaintextBytes);

    const corruptedCiphertext = new Uint8Array(ciphertext);
    corruptedCiphertext[4] ^= 0x01; // flip 1 bit

    await assert.rejects(
      async () => {
        await decryptDocumentContent(corruptedCiphertext, tag, iv, cekRaw);
      },
      /operation failed|tag mismatch|failed/i,
      'Modified ciphertext must cause AES-GCM authentication failure'
    );
  });

  it('3.3 Modified Additional Authenticated Data (AAD) Rejection: AAD mismatch fails decryption', async () => {
    const plaintextBytes = new TextEncoder().encode('INTEGRITY-HEADER-PROTECTED-CONTENT');
    const { cekRaw, ciphertext, iv, tag } = await encryptDocumentContent(
      plaintextBytes,
      'AUTHENTICATED-DOCUMENT-HEADER-ORIGINAL'
    );

    await assert.rejects(
      async () => {
        await decryptDocumentContent(
          ciphertext,
          tag,
          iv,
          cekRaw,
          'AUTHENTICATED-DOCUMENT-HEADER-TAMPERED'
        );
      },
      /operation failed|tag mismatch|failed/i,
      'AAD mismatch must abort AES-GCM decryption'
    );
  });

  it('3.4 Nonce/IV Handling: consecutive encryptions use unique 12-byte IVs', async () => {
    const plaintextBytes = new TextEncoder().encode('SAME-PLAINTEXT-TWICE');
    const enc1 = await encryptDocumentContent(plaintextBytes);
    const enc2 = await encryptDocumentContent(plaintextBytes);

    assert.notDeepStrictEqual(enc1.iv, enc2.iv, 'Each encryption must draw a fresh random IV');
    assert.notDeepStrictEqual(enc1.ciphertext, enc2.ciphertext, 'Identical plaintext with unique IVs yields distinct ciphertexts');
  });
});
