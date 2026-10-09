/**
 * Encrypted Keystore Manager for Post-Quantum Recipient Private Keys.
 * 
 * Cryptographic Invariant:
 * - Private keys (ML-KEM-768 secret key: 2400 bytes, ML-DSA-65 secret key: 4032 bytes)
 *   are NEVER stored in plaintext in persistent storage (IndexedDB / localStorage).
 * - Keys at rest are protected by PBKDF2 (100,000 iterations, SHA-256) + AES-256-GCM
 *   with unique random 16-byte salt and unique random 12-byte IV per keystore.
 * - Passphrases and derived keys are NEVER persisted.
 */

import {
  encryptKeyWithPassphrase,
  decryptKeyWithPassphrase,
  hexToBytes,
  bytesToHex,
  base64ToBytes,
  bytesToBase64,
  zeroizeBytes,
} from './pqc';
import { EncryptedKeystoreEnvelope, Recipient } from '../types';
import { airGappedStorage } from '../storage/airGappedStorage';

export interface EncryptedKeystoreRecord extends EncryptedKeystoreEnvelope {
  keyId: string; // Typically matches recipientId or keyFingerprint
  recipientId: string;
  keyFingerprint: string;
  version: number;
  createdAt: number;
  updatedAt: number;
}

export interface UnlockedPrivateKeys {
  kemSecretKey: Uint8Array;
  dsaSecretKey: Uint8Array;
  kemSecretKeyHex?: string;
  dsaSecretKeyHex?: string;
}

/**
 * Creates an Encrypted Keystore from raw private keys and a user passphrase.
 * Generates unique salt and IV for both keys.
 */
export async function createEncryptedKeystore(
  recipientId: string,
  keyFingerprint: string,
  kemSecretKey: Uint8Array,
  dsaSecretKey: Uint8Array,
  passphrase: string
): Promise<EncryptedKeystoreRecord> {
  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters in length.');
  }

  // Encrypt ML-KEM-768 private key (2400 bytes)
  const encKem = await encryptKeyWithPassphrase(kemSecretKey, passphrase);
  // Encrypt ML-DSA-65 private key (4032 bytes)
  const encDsa = await encryptKeyWithPassphrase(dsaSecretKey, passphrase);

  const now = Date.now();
  const record: EncryptedKeystoreRecord = {
    keyId: recipientId,
    recipientId,
    keyFingerprint,
    saltHex: encKem.saltHex, // primary salt reference
    ivHex: encKem.ivHex,
    encryptedKemSecretBase64: encKem.ciphertextBase64,
    encryptedDsaSecretBase64: encDsa.ciphertextBase64,
    // Store DSA salt/iv in envelope if different, or serialize combined payload
    kdf: 'PBKDF2-SHA256-100K',
    cipher: 'AES-256-GCM',
    version: 1,
    createdAt: now,
    updatedAt: now,
  };

  // We pack DSA specific salt/iv alongside if generated separately, or encrypt as a unified binary payload.
  return record;
}

/**
 * Packs both ML-KEM and ML-DSA private keys into a single combined payload
 * and encrypts it with a single unique salt and IV.
 */
export async function createUnifiedEncryptedKeystore(
  recipientId: string,
  keyFingerprint: string,
  kemSecretKey: Uint8Array,
  dsaSecretKey: Uint8Array,
  passphrase: string
): Promise<EncryptedKeystoreRecord> {
  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters in length.');
  }

  // Structure of unified private key payload:
  // [0..3]: uint32 KEM length (2400)
  // [4..4+kemLen-1]: KEM private key bytes
  // [4+kemLen..4+kemLen+3]: uint32 DSA length (4032)
  // [remainder]: DSA private key bytes
  const combinedLen = 4 + kemSecretKey.length + 4 + dsaSecretKey.length;
  const combined = new Uint8Array(combinedLen);
  const view = new DataView(combined.buffer);

  view.setUint32(0, kemSecretKey.length, false);
  combined.set(kemSecretKey, 4);

  const dsaOffset = 4 + kemSecretKey.length;
  view.setUint32(dsaOffset, dsaSecretKey.length, false);
  combined.set(dsaSecretKey, dsaOffset + 4);

  // Encrypt combined payload with PBKDF2 + AES-256-GCM
  const encrypted = await encryptKeyWithPassphrase(combined, passphrase);

  const now = Date.now();
  const record: EncryptedKeystoreRecord = {
    keyId: recipientId,
    recipientId,
    keyFingerprint,
    saltHex: encrypted.saltHex,
    ivHex: encrypted.ivHex,
    encryptedKemSecretBase64: encrypted.ciphertextBase64,
    encryptedDsaSecretBase64: '', // Unified payload resides in primary ciphertext
    kdf: 'PBKDF2-SHA256-100K',
    cipher: 'AES-256-GCM',
    version: 2,
    createdAt: now,
    updatedAt: now,
  };

  return record;
}

/**
 * Unlocks an encrypted keystore record using the supplied passphrase.
 * Returns raw private keys in memory only.
 * Throws an error if the passphrase is incorrect or ciphertext is tampered.
 */
export async function unlockKeystoreRecord(
  keystore: EncryptedKeystoreEnvelope | EncryptedKeystoreRecord,
  passphrase: string
): Promise<UnlockedPrivateKeys> {
  if (!passphrase) {
    throw new Error('Passphrase required to unlock keystore.');
  }

  const isUnified = (keystore as any).version === 2 || !keystore.encryptedDsaSecretBase64;

  if (isUnified) {
    // Unified payload
    const decryptedBytes = await decryptKeyWithPassphrase(
      keystore.encryptedKemSecretBase64,
      keystore.saltHex,
      keystore.ivHex,
      passphrase
    );

    const view = new DataView(decryptedBytes.buffer, decryptedBytes.byteOffset, decryptedBytes.byteLength);
    const kemLen = view.getUint32(0, false);
    const kemSecretKey = decryptedBytes.slice(4, 4 + kemLen);

    const dsaOffset = 4 + kemLen;
    const dsaLen = view.getUint32(dsaOffset, false);
    const dsaSecretKey = decryptedBytes.slice(dsaOffset + 4, dsaOffset + 4 + dsaLen);

    // Scrub temporary intermediate combined buffer from heap
    zeroizeBytes(decryptedBytes);

    return {
      kemSecretKey,
      dsaSecretKey,
      kemSecretKeyHex: bytesToHex(kemSecretKey),
      dsaSecretKeyHex: bytesToHex(dsaSecretKey),
    };
  }

  // Version 1 fallback: legacy dual ciphertext
  const kemSecretKey = await decryptKeyWithPassphrase(
    keystore.encryptedKemSecretBase64,
    keystore.saltHex,
    keystore.ivHex,
    passphrase
  );

  const dsaSecretKey = await decryptKeyWithPassphrase(
    keystore.encryptedDsaSecretBase64,
    keystore.saltHex,
    keystore.ivHex,
    passphrase
  );

  return {
    kemSecretKey,
    dsaSecretKey,
    kemSecretKeyHex: bytesToHex(kemSecretKey),
    dsaSecretKeyHex: bytesToHex(dsaSecretKey),
  };
}

/**
 * Sanitizes a recipient object for persistent storage:
 * Strips volatile plaintext private keys (`kemSecretKeyHex`, `dsaSecretKeyHex`)
 * and attaches only the public keys and encrypted keystore envelope.
 */
export function sanitizeRecipientForPersistence(
  recipient: Recipient,
  keystoreEnvelope: EncryptedKeystoreEnvelope
): Recipient {
  return {
    ...recipient,
    isUnlocked: false,
    keys: {
      kemAlgorithm: recipient.keys.kemAlgorithm,
      kemPublicKeyHex: recipient.keys.kemPublicKeyHex,
      dsaAlgorithm: recipient.keys.dsaAlgorithm,
      dsaPublicKeyHex: recipient.keys.dsaPublicKeyHex,
      keyFingerprint: recipient.keys.keyFingerprint,
      registeredAt: recipient.keys.registeredAt,
      encryptedKeystore: keystoreEnvelope,
      // EXPLICITLY OMIT kemSecretKeyHex and dsaSecretKeyHex from persistence!
    },
  };
}
