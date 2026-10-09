import './setup.ts';
import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
  generateRecipientPqcKeys,
  encapsulateCekForRecipient,
  decapsulateCekForRecipient,
  hexToBytes,
  bytesToHex,
} from '../src/crypto/pqc.ts';

describe('TEST GROUP 1: ML-KEM-768 (NIST FIPS 203)', () => {
  it('1.1 Key Generation: generates valid ML-KEM-768 key lengths', async () => {
    const rawKeys = ml_kem768.keygen();
    // NIST FIPS 203 ML-KEM-768 specifies:
    // Public Key length = 1184 bytes
    // Secret Key length = 2400 bytes
    assert.strictEqual(rawKeys.publicKey.length, 1184, 'ML-KEM-768 public key must be exactly 1184 bytes');
    assert.strictEqual(rawKeys.secretKey.length, 2400, 'ML-KEM-768 secret key must be exactly 2400 bytes');
  });

  it('1.2 Encapsulation & Decapsulation: produces identical 32-byte shared secret', async () => {
    const keys = ml_kem768.keygen();
    const { cipherText, sharedSecret: senderSecret } = ml_kem768.encapsulate(keys.publicKey);

    // NIST FIPS 203 ML-KEM-768 cipherText length = 1088 bytes
    assert.strictEqual(cipherText.length, 1088, 'ML-KEM-768 ciphertext must be exactly 1088 bytes');
    assert.strictEqual(senderSecret.length, 32, 'Shared secret must be 32 bytes (256 bits)');

    const recipientSecret = ml_kem768.decapsulate(cipherText, keys.secretKey);
    assert.deepStrictEqual(recipientSecret, senderSecret, 'Sender and recipient shared secrets must match exactly');
  });

  it('1.3 Enclave CEK Wrapping: wraps and unwraps 32-byte AES content encryption key', async () => {
    const recipientKeys = ml_kem768.keygen();
    const originalCek = crypto.getRandomValues(new Uint8Array(32));

    const { kemCiphertext, wrappedCek } = await encapsulateCekForRecipient(
      recipientKeys.publicKey,
      originalCek
    );

    assert.strictEqual(kemCiphertext.length, 1088, 'KEM ciphertext must be 1088 bytes');
    // wrappedCek = 12-byte IV + 32-byte ciphertext + 16-byte GCM tag = 60 bytes
    assert.strictEqual(wrappedCek.length, 60, 'Wrapped CEK payload must be 60 bytes');

    const recoveredCek = await decapsulateCekForRecipient(
      recipientKeys.secretKey,
      kemCiphertext,
      wrappedCek
    );

    assert.deepStrictEqual(recoveredCek, originalCek, 'Recovered CEK must be identical to original CEK');
  });

  it('1.4 Wrong Ciphertext Rejection: altered ciphertext yields different or invalid shared secret', async () => {
    const recipientKeys = ml_kem768.keygen();
    const { cipherText } = ml_kem768.encapsulate(recipientKeys.publicKey);

    // Flip bits in KEM ciphertext
    const corruptedCiphertext = new Uint8Array(cipherText);
    corruptedCiphertext[10] ^= 0xff;

    const originalCek = crypto.getRandomValues(new Uint8Array(32));
    const { wrappedCek } = await encapsulateCekForRecipient(
      recipientKeys.publicKey,
      originalCek
    );

    // Decapsulating corrupted KEM ciphertext yields an implicit-rejection pseudo-random key
    // which fails AES-GCM tag verification on the wrapped CEK
    await assert.rejects(
      async () => {
        await decapsulateCekForRecipient(recipientKeys.secretKey, corruptedCiphertext, wrappedCek);
      },
      /operation failed|tag mismatch|failed/i,
      'Corrupted ciphertext must fail AES-GCM unwrap'
    );
  });

  it('1.5 Wrong Key Rejection: decapsulating with another recipient key fails to unwrap CEK', async () => {
    const aliceKeys = ml_kem768.keygen();
    const bobKeys = ml_kem768.keygen();

    const originalCek = crypto.getRandomValues(new Uint8Array(32));
    const { kemCiphertext, wrappedCek } = await encapsulateCekForRecipient(
      aliceKeys.publicKey,
      originalCek
    );

    // Bob attempts to decapsulate Alice's envelope
    await assert.rejects(
      async () => {
        await decapsulateCekForRecipient(bobKeys.secretKey, kemCiphertext, wrappedCek);
      },
      /operation failed|tag mismatch|failed/i,
      'Bob cannot unwrap CEK intended for Alice'
    );
  });
});
