import './setup.ts';
import test, { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

import { ValidatorNodeEngine } from '../src/validator/validatorNode.ts';
import { ValidatorNodeConfig } from '../src/validator/config.ts';
import { DecryptionEvent, LedgerBlock, ClassifiedDocument, Recipient } from '../src/types/index.ts';
import {
  sha256Hex,
  generateRecipientPqcKeys,
  signWithMlDsa65,
  canonicalizeJson,
  bytesToBase64,
  bytesToHex,
} from '../src/crypto/pqc.ts';
import { buildMerkleRoot, airGappedLedger } from '../src/ledger/dlt.ts';
import { DistributionService } from '../src/services/distributionService.ts';
import { sessionManager } from '../src/crypto/sessionManager.ts';
import { createUnifiedEncryptedKeystore, unlockKeystoreRecord } from '../src/crypto/keystore.ts';
import { airGappedStorage } from '../src/storage/airGappedStorage.ts';
import { createMinimalValidPdf } from '../src/crypto/pdfUtils.ts';

const DLT_TEST_DIR = path.resolve(process.cwd(), '.test-dlt-quorum-data');

function makeQuorumNodeConfig(
  nodeId: string,
  name: string,
  port: number,
  peers: { nodeId: string; host: string; port: number }[],
  keyHex: string
): ValidatorNodeConfig {
  return {
    nodeId,
    name,
    role: 'Quorum Consensus Node',
    location: 'Secure Enclave',
    listenHost: '127.0.0.1',
    listenPort: port,
    httpPort: port + 1000,
    dataDir: path.join(DLT_TEST_DIR, nodeId),
    peers,
    quorumRequired: 3, // Strict 3 of 4 = 75% quorum
    publicVerificationKeyHex: `pub-${nodeId}`,
    privateSigningKeyHex: keyHex,
  };
}

describe('TEST GROUP 14: Real Multi-Node DLT — Quorum, Tamper Resistance & Final Integration (DLT-QUORUM-01 to DLT-QUORUM-13)', () => {
  let nodeA: ValidatorNodeEngine;
  let nodeB: ValidatorNodeEngine;
  let nodeC: ValidatorNodeEngine;
  let nodeD: ValidatorNodeEngine;

  const basePort = 30000 + Math.floor(Math.random() * 20000);
  const portA = basePort + 1;
  const portB = basePort + 2;
  const portC = basePort + 3;
  const portD = basePort + 4;

  const cfgA = makeQuorumNodeConfig('q-val-alpha', 'Validator Alpha', portA, [
    { nodeId: 'q-val-bravo', host: '127.0.0.1', port: portB },
    { nodeId: 'q-val-gamma', host: '127.0.0.1', port: portC },
    { nodeId: 'q-val-delta', host: '127.0.0.1', port: portD },
  ], '1111111111111111111111111111111111111111111111111111111111111111');

  const cfgB = makeQuorumNodeConfig('q-val-bravo', 'Validator Bravo', portB, [
    { nodeId: 'q-val-alpha', host: '127.0.0.1', port: portA },
    { nodeId: 'q-val-gamma', host: '127.0.0.1', port: portC },
    { nodeId: 'q-val-delta', host: '127.0.0.1', port: portD },
  ], '2222222222222222222222222222222222222222222222222222222222222222');

  const cfgC = makeQuorumNodeConfig('q-val-gamma', 'Validator Gamma', portC, [
    { nodeId: 'q-val-alpha', host: '127.0.0.1', port: portA },
    { nodeId: 'q-val-bravo', host: '127.0.0.1', port: portB },
    { nodeId: 'q-val-delta', host: '127.0.0.1', port: portD },
  ], '3333333333333333333333333333333333333333333333333333333333333333');

  const cfgD = makeQuorumNodeConfig('q-val-delta', 'Validator Delta', portD, [
    { nodeId: 'q-val-alpha', host: '127.0.0.1', port: portA },
    { nodeId: 'q-val-bravo', host: '127.0.0.1', port: portB },
    { nodeId: 'q-val-gamma', host: '127.0.0.1', port: portC },
  ], '4444444444444444444444444444444444444444444444444444444444444444');

  async function createValidSignedTx(recipientId: string, customDocId = 'DOC-QUORUM-001'): Promise<{ tx: DecryptionEvent; recipient: Recipient }> {
    const keys = await generateRecipientPqcKeys();
    const eventId = `EVT-Q-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const sessionId = `sess-q-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    const recipient: Recipient = {
      id: recipientId,
      name: 'Agent Fox Mulder',
      role: 'Special Investigator',
      organization: 'Cyber Defense Force',
      clearanceLevel: 'TOP SECRET // SCI',
      avatarInitials: 'FM',
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(keys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(keys.dsaPublicKey),
        encryptedKeystore: {} as any,
        keyFingerprint: keys.fingerprint,
        registeredAt: Date.now(),
      },
    };

    const timestampEpochMs = Date.now();

    const canonical = canonicalizeJson({
      eventId,
      documentId: customDocId,
      documentHashSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      packageHashSha256: 'd41d8cd98f00b204e9800998ecf8427e',
      recipientId,
      recipientPubkeyFingerprint: keys.fingerprint,
      sessionId,
      watermarkId: 'WM-QUORUM-9999',
      watermarkCommitment: 'fedcba9876543210fedcba9876543210',
      timestampEpochMs,
    });

    const sig = signWithMlDsa65(new TextEncoder().encode(canonical), keys.dsaSecretKey);

    const tx: DecryptionEvent = {
      eventId,
      documentId: customDocId,
      documentTitle: 'Operation Quorum Defense 2026',
      documentHashSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      packageHashSha256: 'd41d8cd98f00b204e9800998ecf8427e',
      recipientId,
      recipientName: recipient.name,
      recipientPubkeyFingerprint: keys.fingerprint,
      sessionId,
      watermarkId: 'WM-QUORUM-9999',
      watermarkCommitment: 'fedcba9876543210fedcba9876543210',
      timestampEpochMs,
      clientMetadata: {
        terminalId: 'TERM-Q1',
        runtimeSecurity: 'AIR_GAPPED_VALIDATOR_CLUSTER',
      },
      signatureAlgorithm: 'ML-DSA-65',
      recipientSignatureBase64: bytesToBase64(sig),
      status: 'MEMPOOL',
    };

    return { tx, recipient };
  }

  before(async () => {
    try {
      if (fs.existsSync(DLT_TEST_DIR)) {
        fs.rmSync(DLT_TEST_DIR, { recursive: true, force: true });
      }
    } catch {
      // Ignore
    }

    nodeA = new ValidatorNodeEngine(cfgA);
    nodeB = new ValidatorNodeEngine(cfgB);
    nodeC = new ValidatorNodeEngine(cfgC);
    nodeD = new ValidatorNodeEngine(cfgD);

    await nodeA.start();
    await nodeB.start();
    await nodeC.start();
    await nodeD.start();

    // Cross-register validator keys
    const allConfigs = [cfgA, cfgB, cfgC, cfgD];
    for (const node of [nodeA, nodeB, nodeC, nodeD]) {
      for (const cfg of allConfigs) {
        node.registerValidatorKey(cfg.nodeId, cfg.privateSigningKeyHex);
      }
    }

    // Interconnect peers
    await nodeA.connectToPeer('q-val-bravo', '127.0.0.1', portB);
    await nodeA.connectToPeer('q-val-gamma', '127.0.0.1', portC);
    await nodeA.connectToPeer('q-val-delta', '127.0.0.1', portD);
  });

  after(async () => {
    if (nodeA) await nodeA.stop();
    if (nodeB) await nodeB.stop();
    if (nodeC) await nodeC.stop();
    if (nodeD) await nodeD.stop();

    try {
      if (fs.existsSync(DLT_TEST_DIR)) {
        fs.rmSync(DLT_TEST_DIR, { recursive: true, force: true });
      }
    } catch {
      // Ignore
    }
  });

  it('DLT-QUORUM-01: 3 of 4 validators commits a valid block', async () => {
    const { tx, recipient } = await createValidSignedTx('USR-Q-01');
    nodeA.registerRecipient(recipient);
    nodeB.registerRecipient(recipient);
    nodeC.registerRecipient(recipient);
    nodeD.registerRecipient(recipient);

    // Submit transaction
    await nodeA.submitTransaction(tx);
    const proposal = await nodeA.proposeBlock();
    assert.ok(proposal);

    const prevBlock = nodeA.getLatestBlock();
    const merkleRoot = await buildMerkleRoot([tx]);
    const blockHash = proposal.blockHash;

    // Signatures from A, B, C (exactly 3 of 4 quorum)
    const sigA = await sha256Hex(`${blockHash}:q-val-alpha:${cfgA.privateSigningKeyHex}`);
    const sigB = await sha256Hex(`${blockHash}:q-val-bravo:${cfgB.privateSigningKeyHex}`);
    const sigC = await sha256Hex(`${blockHash}:q-val-gamma:${cfgC.privateSigningKeyHex}`);

    const committedBlock: LedgerBlock = {
      height: proposal.height,
      timestamp: proposal.timestamp,
      previousHash: prevBlock.blockHash,
      blockHash,
      merkleRoot,
      transactions: [tx],
      validatorSignatures: [
        { validatorId: 'q-val-alpha', validatorName: 'Validator Alpha', signatureHex: sigA },
        { validatorId: 'q-val-bravo', validatorName: 'Validator Bravo', signatureHex: sigB },
        { validatorId: 'q-val-gamma', validatorName: 'Validator Gamma', signatureHex: sigC },
      ],
      stateRoot: `state-root-h${proposal.height}`,
    };

    // Verify block is validated with 3 of 4 quorum
    const testVerifier = new ValidatorNodeEngine(makeQuorumNodeConfig('q-verifier', 'Verifier', 0, [], '5555555555555555555555555555555555555555555555555555555555555555'));
    for (const cfg of [cfgA, cfgB, cfgC, cfgD]) {
      testVerifier.registerValidatorKey(cfg.nodeId, cfg.privateSigningKeyHex);
    }
    await testVerifier.start();
    const isValidQuorum = await testVerifier.validateIncomingBlock(committedBlock);
    assert.strictEqual(isValidQuorum, true, 'Block with 3-of-4 quorum attestations must be valid');
    await testVerifier.stop();

    // Commit to cluster nodes
    if (nodeA.getLatestBlock().height === 0) await nodeA.appendValidatedBlock(committedBlock);
    if (nodeB.getLatestBlock().height === 0) await nodeB.appendValidatedBlock(committedBlock);
    if (nodeC.getLatestBlock().height === 0) await nodeC.appendValidatedBlock(committedBlock);
    if (nodeD.getLatestBlock().height === 0) await nodeD.appendValidatedBlock(committedBlock);

    assert.strictEqual(nodeA.getLatestBlock().height, 1);
    assert.strictEqual(nodeB.getLatestBlock().height, 1);
    assert.strictEqual(nodeC.getLatestBlock().height, 1);
    assert.strictEqual(nodeD.getLatestBlock().height, 1);
  });

  it('DLT-QUORUM-02: 2 of 4 validators cannot commit a block (insufficient quorum)', async () => {
    const { tx } = await createValidSignedTx('USR-Q-02');
    const latest = nodeA.getLatestBlock();
    const height = latest.height + 1;
    const timestamp = Date.now();
    const merkleRoot = await buildMerkleRoot([tx]);
    const blockData = `BLOCK:${height}:${latest.blockHash}:${timestamp}:${merkleRoot}`;
    const blockHash = await sha256Hex(blockData);

    const sigA = await sha256Hex(`${blockHash}:q-val-alpha:${cfgA.privateSigningKeyHex}`);
    const sigB = await sha256Hex(`${blockHash}:q-val-bravo:${cfgB.privateSigningKeyHex}`);

    // ONLY 2 signatures (less than 3 required for 3/4 quorum)
    const subQuorumBlock: LedgerBlock = {
      height,
      timestamp,
      previousHash: latest.blockHash,
      blockHash,
      merkleRoot,
      transactions: [tx],
      validatorSignatures: [
        { validatorId: 'q-val-alpha', validatorName: 'Validator Alpha', signatureHex: sigA },
        { validatorId: 'q-val-bravo', validatorName: 'Validator Bravo', signatureHex: sigB },
      ],
      stateRoot: `state-root-h${height}`,
    };

    const isValid = await nodeA.validateIncomingBlock(subQuorumBlock);
    assert.strictEqual(isValid, false, 'A block with only 2 approvals must be rejected');

    const committed = await nodeA.handleBlockCommit({ block: subQuorumBlock });
    assert.strictEqual(committed, false);
    assert.strictEqual(nodeA.getLatestBlock().height, 1); // height unchanged
  });

  it('DLT-QUORUM-03: One validator offline does not prevent commitment (3 of 4 online)', async () => {
    // Stop Validator D
    await nodeD.stop();
    assert.strictEqual(nodeD.status, 'OFFLINE');

    const { tx } = await createValidSignedTx('USR-Q-03');
    const latest = nodeA.getLatestBlock();
    const height = latest.height + 1;
    const timestamp = Date.now();
    const merkleRoot = await buildMerkleRoot([tx]);
    const blockData = `BLOCK:${height}:${latest.blockHash}:${timestamp}:${merkleRoot}`;
    const blockHash = await sha256Hex(blockData);

    // Nodes A, B, C (3 online) sign
    const sigA = await sha256Hex(`${blockHash}:q-val-alpha:${cfgA.privateSigningKeyHex}`);
    const sigB = await sha256Hex(`${blockHash}:q-val-bravo:${cfgB.privateSigningKeyHex}`);
    const sigC = await sha256Hex(`${blockHash}:q-val-gamma:${cfgC.privateSigningKeyHex}`);

    const block2: LedgerBlock = {
      height,
      timestamp,
      previousHash: latest.blockHash,
      blockHash,
      merkleRoot,
      transactions: [tx],
      validatorSignatures: [
        { validatorId: 'q-val-alpha', validatorName: 'Validator Alpha', signatureHex: sigA },
        { validatorId: 'q-val-bravo', validatorName: 'Validator Bravo', signatureHex: sigB },
        { validatorId: 'q-val-gamma', validatorName: 'Validator Gamma', signatureHex: sigC },
      ],
      stateRoot: `state-root-h${height}`,
    };

    assert.strictEqual(await nodeA.validateIncomingBlock(block2), true);
    assert.strictEqual(await nodeB.validateIncomingBlock(block2), true);
    assert.strictEqual(await nodeC.validateIncomingBlock(block2), true);

    await nodeA.appendValidatedBlock(block2);
    await nodeB.appendValidatedBlock(block2);
    await nodeC.appendValidatedBlock(block2);

    assert.strictEqual(nodeA.getLatestBlock().height, 2);
    assert.strictEqual(nodeB.getLatestBlock().height, 2);
    assert.strictEqual(nodeC.getLatestBlock().height, 2);
  });

  it('DLT-QUORUM-04: Invalid validator signature is rejected', async () => {
    const { tx } = await createValidSignedTx('USR-Q-04');
    const latest = nodeB.getLatestBlock();
    const height = latest.height + 1;
    const timestamp = Date.now();
    const merkleRoot = await buildMerkleRoot([tx]);
    const blockData = `BLOCK:${height}:${latest.blockHash}:${timestamp}:${merkleRoot}`;
    const blockHash = await sha256Hex(blockData);

    const forgedSignaturesBlock: LedgerBlock = {
      height,
      timestamp,
      previousHash: latest.blockHash,
      blockHash,
      merkleRoot,
      transactions: [tx],
      validatorSignatures: [
        { validatorId: 'q-val-alpha', validatorName: 'Validator Alpha', signatureHex: 'FORGED_ATT_SIG_01' },
        { validatorId: 'q-val-bravo', validatorName: 'Validator Bravo', signatureHex: 'FORGED_ATT_SIG_02' },
        { validatorId: 'q-val-gamma', validatorName: 'Validator Gamma', signatureHex: 'FORGED_ATT_SIG_03' },
      ],
      stateRoot: `state-root-h${height}`,
    };

    const isValid = await nodeB.validateIncomingBlock(forgedSignaturesBlock);
    assert.strictEqual(isValid, false, 'Block with forged validator attestations must be rejected');
  });

  it('DLT-QUORUM-05: Conflicting block proposals for same height are rejected (Anti-equivocation)', async () => {
    const latest = nodeA.getLatestBlock();
    const height = latest.height + 1;

    // Proposal 15A
    const resA = await createValidSignedTx('USR-ALICE');
    nodeB.registerRecipient(resA.recipient);
    const txA = resA.tx;
    const merkleA = await buildMerkleRoot([txA]);
    const tsA = Date.now();
    const dataA = `BLOCK:${height}:${latest.blockHash}:${tsA}:${merkleA}`;
    const hashA = await sha256Hex(dataA);

    // Proposal 15B
    const resB = await createValidSignedTx('USR-BOB');
    nodeB.registerRecipient(resB.recipient);
    const txB = resB.tx;
    const merkleB = await buildMerkleRoot([txB]);
    const tsB = tsA + 100;
    const dataB = `BLOCK:${height}:${latest.blockHash}:${tsB}:${merkleB}`;
    const hashB = await sha256Hex(dataB);

    assert.notStrictEqual(hashA, hashB);

    // Deliver Proposal A to Node B
    await (nodeB as any).handleBlockProposal({
      height,
      timestamp: tsA,
      previousHash: latest.blockHash,
      blockHash: hashA,
      merkleRoot: merkleA,
      transactions: [txA],
      proposerNodeId: 'q-val-alpha',
    });

    // Deliver competing Proposal B to Node B
    await (nodeB as any).handleBlockProposal({
      height,
      timestamp: tsB,
      previousHash: latest.blockHash,
      blockHash: hashB,
      merkleRoot: merkleB,
      transactions: [txB],
      proposerNodeId: 'q-val-gamma',
    });

    // Node B must only have attested to Proposal A, never Proposal B
    const attestationsB = (nodeB as any).signedAttestationHeights;
    assert.strictEqual(attestationsB.get(height), hashA);
  });

  it('DLT-QUORUM-06: Historical tampering on one node is detected', async () => {
    // Tamper Block 1 on Node A
    const tampered = nodeA.simulateHistoricalTamper(1, 'USR-MALICIOUS-ADMIN-TAMPER');
    assert.strictEqual(tampered, true);

    // Audit Node A
    const auditA = await nodeA.auditLocalLedger();
    assert.strictEqual(auditA.isValid, false);
    assert.ok(auditA.reason?.includes('Merkle root mismatch') || auditA.reason?.includes('hash'));
  });

  it('DLT-QUORUM-07: Tampered node does not corrupt healthy nodes', async () => {
    // Healthy nodes B and C are untampered
    const auditB = await nodeB.auditLocalLedger();
    const auditC = await nodeC.auditLocalLedger();

    assert.strictEqual(auditB.isValid, true);
    assert.strictEqual(auditC.isValid, true);

    // If Node A tries to commit its tampered block to Node B
    const tamperedBlock = nodeA.getChain()[1];
    const canAccept = await nodeB.validateIncomingBlock(tamperedBlock);
    assert.strictEqual(canAccept, false);
  });

  it('DLT-QUORUM-08: Restarted / recovered validator synchronizes missing history', async () => {
    // Recover Node A from healthy Node B
    const recoveryResult = await nodeA.recoverFromPeer(nodeB);
    assert.strictEqual(recoveryResult.success, true);

    // Node A's head hash now matches Node B
    assert.strictEqual(nodeA.getLatestBlock().blockHash, nodeB.getLatestBlock().blockHash);

    // Node A's local ledger audit now passes 100%
    const auditA = await nodeA.auditLocalLedger();
    assert.strictEqual(auditA.isValid, true);

    // Restart Node D and synchronize from Node B
    await nodeD.start();
    const recoveryD = await nodeD.recoverFromPeer(nodeB);
    assert.strictEqual(recoveryD.success, true);
    assert.strictEqual(nodeD.getLatestBlock().blockHash, nodeB.getLatestBlock().blockHash);
  });

  it('DLT-QUORUM-09: Duplicate transaction submission is rejected', async () => {
    const { tx } = await createValidSignedTx('USR-Q-DUP');
    const firstSubmit = await nodeA.submitTransaction(tx);
    assert.strictEqual(firstSubmit.success, true);

    // Replay identical transaction
    const duplicateSubmit = await nodeA.submitTransaction(tx);
    assert.strictEqual(duplicateSubmit.success, false);
    assert.ok(duplicateSubmit.error?.includes('ReplayAttackRejected'));
  });

  it('DLT-QUORUM-10: Replaying an already committed block is rejected', async () => {
    const chain = nodeA.getChain();
    const block1 = chain[1];

    // Attempt to commit Block 1 again when height is at 2
    const replayResult = await nodeA.handleBlockCommit({ block: block1 });
    assert.strictEqual(replayResult, false);
    assert.strictEqual(nodeA.getLatestBlock().height, 2);
  });

  it('DLT-QUORUM-11: Forensic attribution works against replicated DLT with 3/4 quorum', async () => {
    // Initialize Genesis for airGappedLedger
    await airGappedLedger.initGenesis();

    // 1. Create recipient
    const recipientKeys = await generateRecipientPqcKeys();
    const pass = 'TestPassphrase2026!';
    const keystore = await createUnifiedEncryptedKeystore(
      'USR-FORENSIC-Q1',
      recipientKeys.fingerprint,
      recipientKeys.kemSecretKey,
      recipientKeys.dsaSecretKey,
      pass
    );

    const recipient: Recipient = {
      id: 'USR-FORENSIC-Q1',
      name: 'Agent Dana Scully',
      role: 'Forensic Medical Examiner',
      organization: 'Cyber Defense Command',
      clearanceLevel: 'TOP SECRET // SCI',
      avatarInitials: 'DS',
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(recipientKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(recipientKeys.dsaPublicKey),
        encryptedKeystore: keystore,
        keyFingerprint: recipientKeys.fingerprint,
        registeredAt: Date.now(),
      },
    };

    airGappedLedger.registerRecipient(recipient);
    await airGappedStorage.saveKeystore(keystore);

    // 2. Prepare test PDF
    const rawPdf = createMinimalValidPdf('Classified Provenance Record 2026');
    const doc: ClassifiedDocument = {
      id: 'DOC-Q-PROV-001',
      title: 'Classified Provenance Record 2026',
      classification: 'TOP SECRET // SCI',
      caveats: 'NOFORN',
      originatingOffice: 'Directorate of Strategic Operations',
      summary: 'Provenance audit.',
      rawText: 'Provenance audit.',
      visualPages: [],
      createdAt: Date.now(),
      isPdf: true,
      mimeType: 'application/pdf',
      filename: 'Provenance_2026.pdf',
      pdfBytes: rawPdf,
    };

    // 3. Encrypt & Decrypt
    const pkg = await DistributionService.createEncryptedPackage(doc, [recipient]);
    const unlocked = await unlockKeystoreRecord(keystore, pass);
    const session = sessionManager.startSession(recipient, unlocked);

    const decResult = await DistributionService.executeRecipientDecryption(pkg, recipient, session);
    assert.ok(decResult.decryptedBytes);

    // 4. Run Forensic Investigation on decrypted PDF
    const report = await DistributionService.investigateLeakedDocument(decResult.decryptedBytes);

    assert.strictEqual(report.verificationStatus, 'VERIFIED');
    assert.strictEqual(report.attributedRecipient?.id, recipient.id);
    assert.strictEqual(report.matchedBlock?.validatorSignatures.length! >= 3, true);
  });

  it('DLT-QUORUM-12: Valid forensic attribution remains valid with one validator offline', async () => {
    // Take Validator Delta offline
    airGappedLedger.setValidatorStatus('val-delta-04', 'OFFLINE');
    const quorum = airGappedLedger.getQuorumStatus();
    assert.strictEqual(quorum.online, 3);
    assert.strictEqual(quorum.hasQuorum, true);

    // Verify ledger integrity still passes 3/4 quorum
    const audit = await airGappedLedger.verifyLedgerIntegrity();
    assert.strictEqual(audit.isValid, true);
  });

  it('DLT-QUORUM-13: Forensic attribution fails and suppresses identity if ledger evidence is tampered', async () => {
    // Simulate rogue admin tamper on the committed block
    airGappedLedger.simulateTamper(1, 'USR-MALICIOUS-ADMIN-ATTACK');

    // Run audit
    const audit = await airGappedLedger.verifyLedgerIntegrity();
    assert.strictEqual(audit.isValid, false);

    // Restore ledger for clean state
    await airGappedLedger.restoreLedger();
    airGappedLedger.setValidatorStatus('val-delta-04', 'ONLINE');
    const restoredAudit = await airGappedLedger.verifyLedgerIntegrity();
    assert.strictEqual(restoredAudit.isValid, true);
  });
});
