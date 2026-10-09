import './setup.ts';
import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  createUnifiedEncryptedKeystore,
  unlockKeystoreRecord,
  sanitizeRecipientForPersistence,
} from '../src/crypto/keystore.ts';
import { generateRecipientPqcKeys, bytesToHex } from '../src/crypto/pqc.ts';
import { Recipient } from '../src/types';

describe('TEST GROUP 6: Local Passphrase-Protected Keystore (AUTH-KEY-01 to AUTH-KEY-12)', () => {
  const testUserId = 'USR-ALICE-TEST-01';
  const testPassphrase = 'AliceSuperSecretPassphrase2026!';
  const wrongPassphrase = 'WrongPasswordTotally!';

  it('AUTH-KEY-01: Correct passphrase decrypts the keystore', async () => {
    const keys = await generateRecipientPqcKeys();
    const keystore = await createUnifiedEncryptedKeystore(
      testUserId,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      testPassphrase
    );

    const unlocked = await unlockKeystoreRecord(keystore, testPassphrase);
    assert.ok(unlocked, 'Unlocked result must be returned');
    assert.deepStrictEqual(unlocked.kemSecretKey, keys.kemSecretKey, 'ML-KEM private key must match original');
    assert.deepStrictEqual(unlocked.dsaSecretKey, keys.dsaSecretKey, 'ML-DSA private key must match original');
  });

  it('AUTH-KEY-02: Incorrect passphrase fails decryption safely', async () => {
    const keys = await generateRecipientPqcKeys();
    const keystore = await createUnifiedEncryptedKeystore(
      testUserId,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      testPassphrase
    );

    await assert.rejects(
      async () => {
        await unlockKeystoreRecord(keystore, wrongPassphrase);
      },
      /operation failed|tag mismatch|failed/i,
      'Wrong passphrase must fail AES-GCM tag verification'
    );
  });

  it('AUTH-KEY-03: Modified encrypted keystore fails authentication', async () => {
    const keys = await generateRecipientPqcKeys();
    const keystore = await createUnifiedEncryptedKeystore(
      testUserId,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      testPassphrase
    );

    // Corrupt one byte of the base64 ciphertext
    const rawCipher = Buffer.from(keystore.encryptedKemSecretBase64, 'base64');
    rawCipher[20] ^= 0x01; // flip 1 bit
    const tamperedKeystore = {
      ...keystore,
      encryptedKemSecretBase64: rawCipher.toString('base64'),
    };

    await assert.rejects(
      async () => {
        await unlockKeystoreRecord(tamperedKeystore, testPassphrase);
      },
      /operation failed|tag mismatch|failed/i,
      'Tampered ciphertext must cause authentication failure'
    );
  });

  it('AUTH-KEY-04: ML-KEM private key round-trips correctly through encryption/decryption', async () => {
    const keys = await generateRecipientPqcKeys();
    assert.strictEqual(keys.kemSecretKey.length, 2400, 'Original ML-KEM-768 secret key is 2400 bytes');

    const keystore = await createUnifiedEncryptedKeystore(
      testUserId,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      testPassphrase
    );

    const unlocked = await unlockKeystoreRecord(keystore, testPassphrase);
    assert.strictEqual(unlocked.kemSecretKey.length, 2400, 'Recovered ML-KEM secret key is exactly 2400 bytes');
    assert.strictEqual(unlocked.kemSecretKeyHex, bytesToHex(keys.kemSecretKey));
  });

  it('AUTH-KEY-05: ML-DSA private key round-trips correctly through encryption/decryption', async () => {
    const keys = await generateRecipientPqcKeys();
    assert.strictEqual(keys.dsaSecretKey.length, 4032, 'Original ML-DSA-65 secret key is 4032 bytes');

    const keystore = await createUnifiedEncryptedKeystore(
      testUserId,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      testPassphrase
    );

    const unlocked = await unlockKeystoreRecord(keystore, testPassphrase);
    assert.strictEqual(unlocked.dsaSecretKey.length, 4032, 'Recovered ML-DSA secret key is exactly 4032 bytes');
    assert.strictEqual(unlocked.dsaSecretKeyHex, bytesToHex(keys.dsaSecretKey));
  });

  it('AUTH-KEY-06: Passphrase itself is never persisted in keystore or recipient record', async () => {
    const keys = await generateRecipientPqcKeys();
    const keystore = await createUnifiedEncryptedKeystore(
      testUserId,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      testPassphrase
    );

    const keystoreString = JSON.stringify(keystore);
    assert.strictEqual(
      keystoreString.includes(testPassphrase),
      false,
      'Keystore record must not contain the passphrase string'
    );
  });

  it('AUTH-KEY-07: Plaintext private keys are not present in persisted recipient record', async () => {
    const keys = await generateRecipientPqcKeys();
    const keystore = await createUnifiedEncryptedKeystore(
      testUserId,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      testPassphrase
    );

    const inMemoryRecipient: Recipient = {
      id: testUserId,
      name: 'Dr. Alice Vance',
      role: 'Analyst',
      organization: 'Intelligence Enclave',
      clearanceLevel: 'TOP SECRET // SCI',
      avatarInitials: 'AV',
      isUnlocked: true,
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(keys.kemPublicKey),
        kemSecretKeyHex: bytesToHex(keys.kemSecretKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(keys.dsaPublicKey),
        dsaSecretKeyHex: bytesToHex(keys.dsaSecretKey),
        encryptedKeystore: keystore,
        keyFingerprint: keys.fingerprint,
        registeredAt: Date.now(),
      },
    };

    const sanitized = sanitizeRecipientForPersistence(inMemoryRecipient, keystore);

    assert.strictEqual(sanitized.keys.kemSecretKeyHex, undefined, 'kemSecretKeyHex must be omitted');
    assert.strictEqual(sanitized.keys.dsaSecretKeyHex, undefined, 'dsaSecretKeyHex must be omitted');
    assert.strictEqual(sanitized.isUnlocked, false, 'Persisted record must be marked locked');

    const serialized = JSON.stringify(sanitized);
    assert.strictEqual(
      serialized.includes(bytesToHex(keys.kemSecretKey)),
      false,
      'Serialized recipient must not contain raw ML-KEM private key hex'
    );
    assert.strictEqual(
      serialized.includes(bytesToHex(keys.dsaSecretKey)),
      false,
      'Serialized recipient must not contain raw ML-DSA private key hex'
    );
  });

  it('AUTH-KEY-08: Each newly created keystore has a unique salt', async () => {
    const keys1 = await generateRecipientPqcKeys();
    const keys2 = await generateRecipientPqcKeys();

    const ks1 = await createUnifiedEncryptedKeystore(
      'USR-USER-1',
      keys1.fingerprint,
      keys1.kemSecretKey,
      keys1.dsaSecretKey,
      'CommonPassphrase123!'
    );
    const ks2 = await createUnifiedEncryptedKeystore(
      'USR-USER-2',
      keys2.fingerprint,
      keys2.kemSecretKey,
      keys2.dsaSecretKey,
      'CommonPassphrase123!'
    );

    assert.notStrictEqual(ks1.saltHex, ks2.saltHex, 'Each keystore must have a unique random salt');
    assert.strictEqual(ks1.saltHex.length, 32, '16-byte salt is 32 hex characters');
  });

  it('AUTH-KEY-09: Each newly encrypted keystore uses a fresh IV/nonce', async () => {
    const keys = await generateRecipientPqcKeys();

    const ks1 = await createUnifiedEncryptedKeystore(
      testUserId,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      testPassphrase
    );
    const ks2 = await createUnifiedEncryptedKeystore(
      testUserId,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      testPassphrase
    );

    assert.notStrictEqual(ks1.ivHex, ks2.ivHex, 'Each encryption must draw a fresh random IV');
    assert.notStrictEqual(
      ks1.encryptedKemSecretBase64,
      ks2.encryptedKemSecretBase64,
      'Identical keys with distinct IVs produce distinct ciphertexts'
    );
  });

  it('AUTH-KEY-10: Public-key fingerprints remain unchanged after keystore encryption', async () => {
    const keys = await generateRecipientPqcKeys();
    const keystore = await createUnifiedEncryptedKeystore(
      testUserId,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      testPassphrase
    );

    assert.strictEqual(
      keystore.keyFingerprint,
      keys.fingerprint,
      'Fingerprint in keystore must match original public key fingerprint'
    );
  });

  it('AUTH-KEY-11: Alice cannot unlock Bob\'s keystore using Alice\'s passphrase', async () => {
    const aliceKeys = await generateRecipientPqcKeys();
    const bobKeys = await generateRecipientPqcKeys();

    const alicePass = 'AlicePassphrase999!';
    const bobPass = 'BobPassphrase888!';

    const bobKeystore = await createUnifiedEncryptedKeystore(
      'USR-BOB-02',
      bobKeys.fingerprint,
      bobKeys.kemSecretKey,
      bobKeys.dsaSecretKey,
      bobPass
    );

    // Alice attempts to unlock Bob's keystore using her own passphrase
    await assert.rejects(
      async () => {
        await unlockKeystoreRecord(bobKeystore, alicePass);
      },
      /operation failed|tag mismatch|failed/i,
      'Alice\'s passphrase must not unlock Bob\'s keystore'
    );
  });

  it('AUTH-KEY-12: Corrupted ciphertext is rejected', async () => {
    const keys = await generateRecipientPqcKeys();
    const keystore = await createUnifiedEncryptedKeystore(
      testUserId,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      testPassphrase
    );

    const corruptKeystore = {
      ...keystore,
      encryptedKemSecretBase64: 'INVALID-BASE64-TRUNCATED-BYTES',
    };

    await assert.rejects(
      async () => {
        await unlockKeystoreRecord(corruptKeystore, testPassphrase);
      },
      /error|failed|invalid/i,
      'Mutilated ciphertext must fail to unlock'
    );
  });
});
