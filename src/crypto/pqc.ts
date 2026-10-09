/**
 * Post-Quantum Cryptographic Services Module.
 * Strictly uses NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65).
 * Uses AES-256-GCM for symmetric document encryption.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { Recipient, RecipientKeyMetadata } from '../types';

// ==========================================
// Hex & Base64 Encoders / Decoders
// ==========================================

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.trim().replace(/^0x/, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Best-effort zeroization of sensitive typed-array memory buffers.
 * Explicitly overwrites memory slots with zeros.
 */
export function zeroizeBytes(buffer: Uint8Array | null | undefined): void {
  if (!buffer || !(buffer instanceof Uint8Array)) return;
  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = 0;
  }
}

/**
 * Computes canonical Authenticated Additional Data (AAD) binding document identity and hash.
 */
export function computeDocumentAad(documentId: string, documentHashSha256: string): string {
  return `SIH26237-AAD:v1:${documentId}:${documentHashSha256.toLowerCase().trim()}`;
}

// ==========================================
// Hashing & Key Derivation (SHA-256, HKDF)
// ==========================================

export async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data as ArrayBufferView<ArrayBuffer>);
  return new Uint8Array(hashBuffer);
}

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const inputBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hashBytes = await sha256Bytes(inputBytes);
  return bytesToHex(hashBytes);
}

/**
 * HKDF-SHA256 Extract-and-Expand to derive a 256-bit Key Encryption Key (KEK)
 * from the post-quantum shared secret.
 */
export async function deriveKekFromSharedSecret(
  sharedSecret: Uint8Array,
  infoString = 'DOC-KEY-WRAP-V1'
): Promise<CryptoKey> {
  const salt = new TextEncoder().encode('SIH-AIRGAP-PQC-SALT-2026');
  const info = new TextEncoder().encode(infoString);

  // Import raw shared secret into Web Crypto HKDF
  const baseKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret as ArrayBufferView<ArrayBuffer>,
    'HKDF',
    false,
    ['deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as ArrayBufferView<ArrayBuffer>,
      info: info as ArrayBufferView<ArrayBuffer>,
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

// ==========================================
// Post-Quantum Key Generation (ML-KEM & ML-DSA)
// ==========================================

export interface GeneratedPqcKeys {
  kemPublicKey: Uint8Array;
  kemSecretKey: Uint8Array;
  dsaPublicKey: Uint8Array;
  dsaSecretKey: Uint8Array;
  fingerprint: string;
}

export async function generateRecipientPqcKeys(): Promise<GeneratedPqcKeys> {
  // 1. Generate ML-KEM-768 keypair (NIST FIPS 203)
  const kemKeys = ml_kem768.keygen();

  // 2. Generate ML-DSA-65 keypair (NIST FIPS 204)
  const dsaKeys = ml_dsa65.keygen();

  // 3. Compute public key fingerprint (SHA-256 truncated to 16 hex chars / 64 bits)
  const combinedPub = new Uint8Array(kemKeys.publicKey.length + dsaKeys.publicKey.length);
  combinedPub.set(kemKeys.publicKey, 0);
  combinedPub.set(dsaKeys.publicKey, kemKeys.publicKey.length);
  const fpFull = await sha256Hex(combinedPub);
  const fingerprint = fpFull.slice(0, 16);

  return {
    kemPublicKey: kemKeys.publicKey,
    kemSecretKey: kemKeys.secretKey,
    dsaPublicKey: dsaKeys.publicKey,
    dsaSecretKey: dsaKeys.secretKey,
    fingerprint,
  };
}

// ==========================================
// Symmetric Document Encryption (AES-256-GCM)
// ==========================================

export interface SymmetricEncryptionResult {
  cekRaw: Uint8Array;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

export async function encryptDocumentContent(
  plaintextBytes: Uint8Array,
  aadString = 'AUTHENTICATED-DOCUMENT-HEADER'
): Promise<SymmetricEncryptionResult> {
  // Generate a random 256-bit Content Encryption Key (CEK)
  const cekRaw = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit standard GCM IV
  const aad = new TextEncoder().encode(aadString);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    cekRaw as ArrayBufferView<ArrayBuffer>,
    'AES-GCM',
    false,
    ['encrypt']
  );

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as ArrayBufferView<ArrayBuffer>,
      additionalData: aad as ArrayBufferView<ArrayBuffer>,
      tagLength: 128,
    },
    cryptoKey,
    plaintextBytes as ArrayBufferView<ArrayBuffer>
  );

  // Split ciphertext and 16-byte auth tag
  const encArray = new Uint8Array(encryptedBuffer);
  const ciphertext = encArray.slice(0, encArray.length - 16);
  const tag = encArray.slice(encArray.length - 16);

  return {
    cekRaw,
    ciphertext,
    iv,
    tag,
  };
}

export async function decryptDocumentContent(
  ciphertext: Uint8Array,
  tag: Uint8Array,
  iv: Uint8Array,
  cekRaw: Uint8Array,
  aadString = 'AUTHENTICATED-DOCUMENT-HEADER'
): Promise<Uint8Array> {
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    cekRaw as ArrayBufferView<ArrayBuffer>,
    'AES-GCM',
    false,
    ['decrypt']
  );

  const primaryAad = new TextEncoder().encode(aadString);

  // Strict AAD enforcement: No fallback to legacy or weaker headers!
  // Any mismatch in documentId, documentHash, or classification immediately throws OperationError.
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv as ArrayBufferView<ArrayBuffer>,
      additionalData: primaryAad as ArrayBufferView<ArrayBuffer>,
      tagLength: 128,
    },
    cryptoKey,
    combined as ArrayBufferView<ArrayBuffer>
  );

  return new Uint8Array(decryptedBuffer);
}

// ==========================================
// ML-KEM-768 Enveloping (Broadcast Encrypt)
// ==========================================

export async function encapsulateCekForRecipient(
  recipientKemPublicKey: Uint8Array,
  cekRaw: Uint8Array
): Promise<{ kemCiphertext: Uint8Array; wrappedCek: Uint8Array }> {
  // 1. Run ML-KEM-768 encapsulation
  const { cipherText: kemCiphertext, sharedSecret } = ml_kem768.encapsulate(recipientKemPublicKey);

  // 2. Derive KEK via HKDF-SHA256
  const kek = await deriveKekFromSharedSecret(sharedSecret);

  // 3. Immediately zeroize volatile sharedSecret from memory
  zeroizeBytes(sharedSecret);

  // 4. Encrypt (wrap) the 32-byte CEK using AES-GCM
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedBuf = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: wrapIv as ArrayBufferView<ArrayBuffer>,
    },
    kek,
    cekRaw as ArrayBufferView<ArrayBuffer>
  );

  // Prepend the 12-byte IV to the wrapped CEK payload
  const combinedWrapped = new Uint8Array(12 + wrappedBuf.byteLength);
  combinedWrapped.set(wrapIv, 0);
  combinedWrapped.set(new Uint8Array(wrappedBuf), 12);

  return {
    kemCiphertext,
    wrappedCek: combinedWrapped,
  };
}

export async function decapsulateCekForRecipient(
  recipientKemSecretKey: Uint8Array,
  kemCiphertext: Uint8Array,
  wrappedCekPayload: Uint8Array
): Promise<Uint8Array> {
  // 1. Run ML-KEM-768 decapsulation
  const sharedSecret = ml_kem768.decapsulate(kemCiphertext, recipientKemSecretKey);

  // 2. Derive KEK via HKDF-SHA256
  const kek = await deriveKekFromSharedSecret(sharedSecret);

  // 3. Immediately zeroize volatile sharedSecret from memory
  zeroizeBytes(sharedSecret);

  // 4. Decrypt (unwrap) CEK
  const wrapIv = wrappedCekPayload.slice(0, 12);
  const wrapData = wrappedCekPayload.slice(12);

  const unwrappedBuf = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: wrapIv as ArrayBufferView<ArrayBuffer>,
    },
    kek,
    wrapData as ArrayBufferView<ArrayBuffer>
  );

  return new Uint8Array(unwrappedBuf);
}

// ==========================================
// ML-DSA-65 Post-Quantum Signing (FIPS 204)
// ==========================================

export function signWithMlDsa65(
  messageBytes: Uint8Array,
  dsaSecretKey: Uint8Array
): Uint8Array {
  return ml_dsa65.sign(messageBytes, dsaSecretKey);
}

export function verifyMlDsa65(
  signature: Uint8Array,
  messageBytes: Uint8Array,
  dsaPublicKey: Uint8Array
): boolean {
  try {
    // ML-DSA-65 public key is strictly 1952 bytes; signature is 3309 bytes
    if (!dsaPublicKey || dsaPublicKey.length !== 1952 || !signature || signature.length !== 3309) {
      return false;
    }
    return ml_dsa65.verify(signature, messageBytes, dsaPublicKey);
  } catch (_err) {
    return false;
  }
}

// ==========================================
// Encrypted Keystore Lifecycle (PBKDF2 + AES-GCM)
// ==========================================

export async function encryptKeyWithPassphrase(
  secretKeyBytes: Uint8Array,
  passphrase: string
): Promise<{ saltHex: string; ivHex: string; ciphertextBase64: string }> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as ArrayBufferView<ArrayBuffer>,
      iterations: 100000,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const encryptedBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as ArrayBufferView<ArrayBuffer> },
    derivedKey,
    secretKeyBytes as ArrayBufferView<ArrayBuffer>
  );

  return {
    saltHex: bytesToHex(salt),
    ivHex: bytesToHex(iv),
    ciphertextBase64: bytesToBase64(new Uint8Array(encryptedBuf)),
  };
}

export async function decryptKeyWithPassphrase(
  ciphertextBase64: string,
  saltHex: string,
  ivHex: string,
  passphrase: string
): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const salt = hexToBytes(saltHex);
  const iv = hexToBytes(ivHex);
  const cipherBytes = base64ToBytes(ciphertextBase64);

  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as ArrayBufferView<ArrayBuffer>,
      iterations: 100000,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const decryptedBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as ArrayBufferView<ArrayBuffer> },
    derivedKey,
    cipherBytes as ArrayBufferView<ArrayBuffer>
  );

  return new Uint8Array(decryptedBuf);
}

// RFC 8785 Canonical JSON Serialization (JCS)
export function canonicalizeJson(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalizeJson).join(',') + ']';
  }
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(
    (key) => JSON.stringify(key) + ':' + canonicalizeJson(obj[key])
  );
  return '{' + pairs.join(',') + '}';
}
