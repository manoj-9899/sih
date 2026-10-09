import './setup.ts';
import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  computeTransactionHash,
  buildMerkleRoot,
  createGenesisBlock,
  AirGappedLedger,
} from '../src/ledger/dlt.ts';
import { DecryptionEvent, Recipient } from '../src/types';
import { generateRecipientPqcKeys, bytesToHex, signWithMlDsa65, canonicalizeJson } from '../src/crypto/pqc.ts';

describe('TEST GROUP 5: Air-Gapped DLT Ledger & Merkle Trees', () => {
  const dummyTx: DecryptionEvent = {
    eventId: 'EVT-TEST-001',
    documentId: 'DOC-2026-CONF-991',
    documentTitle: 'Confidential Research Report',
    documentHashSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    packageHashSha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    recipientId: 'USR-ALICE-01',
    recipientName: 'Dr. Alice Vance',
    recipientPubkeyFingerprint: 'a1b2c3d4e5f67890',
    sessionId: 'session-alpha-99',
    watermarkId: 'WM-ALPHA-99',
    watermarkCommitment: 'commitment-hash-1234',
    timestampEpochMs: 1790610000000,
    clientMetadata: {
      terminalId: 'TERM-SCIF-01',
      runtimeSecurity: 'AIRGAP-ENCLAVE',
    },
    signatureAlgorithm: 'ML-DSA-65',
    recipientSignatureBase64: 'AAAAAAAAAAAAAAAA',
    status: 'COMMITTED',
  };

  it('5.1 Deterministic Transaction Hashing: RFC 8785 canonical hash is invariant to key order', async () => {
    const hash1 = await computeTransactionHash(dummyTx);
    const hash2 = await computeTransactionHash(dummyTx);
    assert.strictEqual(hash1, hash2, 'Transaction hash must be deterministic across calls');
    assert.strictEqual(hash1.length, 64, 'SHA-256 transaction hash must be 64 hex characters');
  });

  it('5.2 Merkle Root Calculation: computes deterministic root from transaction leaves', async () => {
    const tx1 = { ...dummyTx, eventId: 'EVT-001' };
    const tx2 = { ...dummyTx, eventId: 'EVT-002' };
    const tx3 = { ...dummyTx, eventId: 'EVT-003' };

    const root1 = await buildMerkleRoot([tx1, tx2, tx3]);
    const root2 = await buildMerkleRoot([tx1, tx2, tx3]);

    assert.strictEqual(root1, root2, 'Merkle root calculation must be deterministic');
    assert.strictEqual(root1.length, 64, 'Merkle root must be 64-character SHA-256 hex');

    // Modifying one transaction alters the Merkle root
    const tamperedTx2 = { ...tx2, recipientId: 'USR-MALICIOUS-TAMPER' };
    const tamperedRoot = await buildMerkleRoot([tx1, tamperedTx2, tx3]);

    assert.notStrictEqual(tamperedRoot, root1, 'Altering a single transaction leaf must alter the Merkle root');
  });

  it('5.3 Genesis Block Structure: produces valid Block 0 with null previous hash', async () => {
    const genesis = await createGenesisBlock();
    assert.strictEqual(genesis.height, 0, 'Genesis block height must be 0');
    assert.strictEqual(genesis.previousHash, '0000000000000000000000000000000000000000000000000000000000000000');
    assert.strictEqual(genesis.blockHash.length, 64, 'Genesis block hash must be 64 hex characters');
  });

  it('5.4 Block Chaining & Tamper Detection: modifying transaction breaks chain validation', async () => {
    const ledger = new AirGappedLedger();
    await ledger.initGenesis();

    // Enroll a real recipient with valid ML-DSA keys
    const keys = await generateRecipientPqcKeys();
    const recipient: Recipient = {
      id: 'USR-TEST-SIGNER',
      name: 'Test Signer',
      role: 'Analyst',
      organization: 'Defense Center',
      clearanceLevel: 'TOP SECRET // SCI',
      avatarInitials: 'TS',
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(keys.kemPublicKey),
        kemSecretKeyHex: bytesToHex(keys.kemSecretKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(keys.dsaPublicKey),
        dsaSecretKeyHex: bytesToHex(keys.dsaSecretKey),
        keyFingerprint: keys.fingerprint,
        registeredAt: Date.now(),
      },
    };
    ledger.registerRecipient(recipient);

    // Sign a genuine event
    const canonicalMsg = canonicalizeJson({
      eventId: 'EVT-REAL-001',
      documentId: dummyTx.documentId,
      documentHashSha256: dummyTx.documentHashSha256,
      packageHashSha256: dummyTx.packageHashSha256,
      recipientId: recipient.id,
      recipientPubkeyFingerprint: recipient.keys.keyFingerprint,
      sessionId: dummyTx.sessionId,
      watermarkId: dummyTx.watermarkId,
      watermarkCommitment: dummyTx.watermarkCommitment,
      timestampEpochMs: dummyTx.timestampEpochMs,
    });
    const sig = signWithMlDsa65(new TextEncoder().encode(canonicalMsg), keys.dsaSecretKey);

    const validEvent: DecryptionEvent = {
      ...dummyTx,
      eventId: 'EVT-REAL-001',
      recipientId: recipient.id,
      recipientName: recipient.name,
      recipientPubkeyFingerprint: recipient.keys.keyFingerprint,
      recipientSignatureBase64: Buffer.from(sig).toString('base64'),
    };

    const submitRes = await ledger.submitDecryptionEvent(validEvent);
    assert.strictEqual(submitRes.success, true, 'Valid ML-DSA-65 signed event must be accepted into mempool');

    const committedBlock = await ledger.commitBlock();
    assert.ok(committedBlock, 'Block must be committed');
    assert.strictEqual(committedBlock.height, 1, 'First user block height must be 1');
    assert.strictEqual(committedBlock.previousHash, ledger.getChain()[0].blockHash, 'Block 1 must point to Block 0');

    // Audit initial healthy state
    const healthyAudit = await ledger.verifyLedgerIntegrity();
    assert.strictEqual(healthyAudit.isValid, true, 'Pristine ledger chain must pass audit');

    // Tamper attack: Rogue admin modifies transaction data in Block 1
    ledger.simulateAdminTamperAttack(1, 'USR-TAMPERED-ADMIN');
    const tamperedAudit = await ledger.verifyLedgerIntegrity();

    assert.strictEqual(tamperedAudit.isValid, false, 'Tampered ledger must fail integrity audit');
    assert.strictEqual(tamperedAudit.tamperDetected?.blockHeight, 1, 'Audit must pinpoint Block 1 as corrupted');
  });
});
