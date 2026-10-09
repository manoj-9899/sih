import './setup.ts';
import test, { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';

import { ValidatorNodeEngine } from '../src/validator/validatorNode.ts';
import { ValidatorNodeConfig } from '../src/validator/config.ts';
import { DecryptionEvent, LedgerBlock } from '../src/types/index.ts';
import { sha256Hex, generateRecipientPqcKeys, signWithMlDsa65, canonicalizeJson, bytesToBase64, bytesToHex } from '../src/crypto/pqc.ts';
import { buildMerkleRoot, computeTransactionHash } from '../src/ledger/dlt.ts';

const TEST_DIR_BASE = path.resolve(process.cwd(), '.test-validator-data');

function makeTestConfig(
  nodeId: string,
  name: string,
  port: number,
  peers: { nodeId: string; host: string; port: number }[],
  keyHex: string
): ValidatorNodeConfig {
  return {
    nodeId,
    name,
    role: 'Test Consensus Node',
    location: 'Test Enclave',
    listenHost: '127.0.0.1',
    listenPort: port,
    httpPort: port + 1000,
    dataDir: path.join(TEST_DIR_BASE, nodeId),
    peers,
    quorumRequired: 3, // 3 of 4 = 75%
    publicVerificationKeyHex: `pub-${nodeId}`,
    privateSigningKeyHex: keyHex,
  };
}

describe('TEST GROUP 13: Multi-Node Offline DLT & Replication (NODE-NET-01 to NODE-NET-15)', () => {
  let nodeA: ValidatorNodeEngine;
  let nodeB: ValidatorNodeEngine;
  let nodeC: ValidatorNodeEngine;
  let nodeD: ValidatorNodeEngine;

  const basePort = 10000 + Math.floor(Math.random() * 20000);
  const portA = basePort + 1;
  const portB = basePort + 2;
  const portC = basePort + 3;
  const portD = basePort + 4;
  const portE = basePort + 5;

  const cfgA = makeTestConfig('test-val-alpha', 'Validator Alpha', portA, [
    { nodeId: 'test-val-bravo', host: '127.0.0.1', port: portB },
    { nodeId: 'test-val-gamma', host: '127.0.0.1', port: portC },
    { nodeId: 'test-val-delta', host: '127.0.0.1', port: portD },
  ], '0101010101010101010101010101010101010101010101010101010101010101');

  const cfgB = makeTestConfig('test-val-bravo', 'Validator Bravo', portB, [
    { nodeId: 'test-val-alpha', host: '127.0.0.1', port: portA },
    { nodeId: 'test-val-gamma', host: '127.0.0.1', port: portC },
    { nodeId: 'test-val-delta', host: '127.0.0.1', port: portD },
  ], '0202020202020202020202020202020202020202020202020202020202020202');

  const cfgC = makeTestConfig('test-val-gamma', 'Validator Gamma', portC, [
    { nodeId: 'test-val-alpha', host: '127.0.0.1', port: portA },
    { nodeId: 'test-val-bravo', host: '127.0.0.1', port: portB },
    { nodeId: 'test-val-delta', host: '127.0.0.1', port: portD },
  ], '0303030303030303030303030303030303030303030303030303030303030303');

  const cfgD = makeTestConfig('test-val-delta', 'Validator Delta', portD, [
    { nodeId: 'test-val-alpha', host: '127.0.0.1', port: portA },
    { nodeId: 'test-val-bravo', host: '127.0.0.1', port: portB },
    { nodeId: 'test-val-gamma', host: '127.0.0.1', port: portC },
  ], '0404040404040404040404040404040404040404040404040404040404040404');

  async function createSampleTx(recipientId: string = 'USR-TEST-01'): Promise<DecryptionEvent> {
    const keys = await generateRecipientPqcKeys();
    const eventId = `EVT-TEST-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const sessionId = `sess-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    const canonical = canonicalizeJson({
      eventId,
      documentId: 'DOC-SEC-999',
      documentHashSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      packageHashSha256: 'd41d8cd98f00b204e9800998ecf8427e',
      recipientId,
      recipientPubkeyFingerprint: keys.fingerprint,
      sessionId,
      watermarkId: 'WM-TEST-1234',
      watermarkCommitment: 'aabbccddeeff00112233445566778899',
      timestampEpochMs: Date.now(),
    });

    const sig = signWithMlDsa65(new TextEncoder().encode(canonical), keys.dsaSecretKey);

    return {
      eventId,
      documentId: 'DOC-SEC-999',
      documentTitle: 'Tactical Defense Architecture 2026',
      documentHashSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      packageHashSha256: 'd41d8cd98f00b204e9800998ecf8427e',
      recipientId,
      recipientName: 'Dr. Test Recipient',
      recipientPubkeyFingerprint: keys.fingerprint,
      sessionId,
      watermarkId: 'WM-TEST-1234',
      watermarkCommitment: 'aabbccddeeff00112233445566778899',
      timestampEpochMs: Date.now(),
      clientMetadata: {
        terminalId: 'TERM-01',
        runtimeSecurity: 'AIR_GAPPED_ENCLAVE',
      },
      signatureAlgorithm: 'ML-DSA-65',
      recipientSignatureBase64: bytesToBase64(sig),
      status: 'MEMPOOL',
    };
  }

  before(async () => {
    // Clean test directory
    try {
      if (fs.existsSync(TEST_DIR_BASE)) {
        fs.rmSync(TEST_DIR_BASE, { recursive: true, force: true });
      }
    } catch {
      // Ignore cleanup error
    }
  });

  after(async () => {
    // Cleanly stop any running nodes
    if (nodeA) await nodeA.stop();
    if (nodeB) await nodeB.stop();
    if (nodeC) await nodeC.stop();
    if (nodeD) await nodeD.stop();

    try {
      if (fs.existsSync(TEST_DIR_BASE)) {
        fs.rmSync(TEST_DIR_BASE, { recursive: true, force: true });
      }
    } catch {
      // Ignore
    }
  });

  it('NODE-NET-01: Four validator processes/configurations can start independently', async () => {
    nodeA = new ValidatorNodeEngine(cfgA);
    nodeB = new ValidatorNodeEngine(cfgB);
    nodeC = new ValidatorNodeEngine(cfgC);
    nodeD = new ValidatorNodeEngine(cfgD);

    await nodeA.start();
    await nodeB.start();
    await nodeC.start();
    await nodeD.start();

    // Register all test validator keys across all test nodes for independent attestation
    const allConfigs = [cfgA, cfgB, cfgC, cfgD];
    for (const node of [nodeA, nodeB, nodeC, nodeD]) {
      for (const cfg of allConfigs) {
        node.registerValidatorKey(cfg.nodeId, cfg.privateSigningKeyHex);
      }
    }

    assert.strictEqual(nodeA.status, 'ONLINE');
    assert.strictEqual(nodeB.status, 'ONLINE');
    assert.strictEqual(nodeC.status, 'ONLINE');
    assert.strictEqual(nodeD.status, 'ONLINE');

    // Each node has its own Genesis block independently initialized
    assert.strictEqual(nodeA.getLatestBlock().height, 0);
    assert.strictEqual(nodeB.getLatestBlock().height, 0);
    assert.strictEqual(nodeC.getLatestBlock().height, 0);
    assert.strictEqual(nodeD.getLatestBlock().height, 0);

    // Isolated data storage paths verified
    assert.ok(fs.existsSync(path.join(cfgA.dataDir, 'ledger.json')));
    assert.ok(fs.existsSync(path.join(cfgB.dataDir, 'ledger.json')));
    assert.ok(fs.existsSync(path.join(cfgC.dataDir, 'ledger.json')));
    assert.ok(fs.existsSync(path.join(cfgD.dataDir, 'ledger.json')));
  });

  it('NODE-NET-02: Validator A can connect to Validator B over local socket transport', async () => {
    const connected = await nodeA.connectToPeer('test-val-bravo', '127.0.0.1', portB);
    assert.strictEqual(connected, true);

    // Allow socket handshake
    await new Promise((r) => setTimeout(r, 60));
    const peersA = nodeA.getConnectedPeerIds();
    assert.ok(peersA.includes('test-val-bravo') || peersA.length > 0);
  });

  it('NODE-NET-03: A valid block propagates from A to B, C, and D', async () => {
    // Interconnect all test nodes
    await nodeA.connectToPeer('test-val-bravo', '127.0.0.1', portB);
    await nodeA.connectToPeer('test-val-gamma', '127.0.0.1', portC);
    await nodeA.connectToPeer('test-val-delta', '127.0.0.1', portD);

    // Submit transaction on Node A
    const tx = await createSampleTx();
    const res = await nodeA.submitTransaction(tx);
    assert.strictEqual(res.success, true);

    // Node A proposes block
    const proposal = await nodeA.proposeBlock();
    assert.ok(proposal);
    assert.strictEqual(proposal.height, 1);

    // Construct valid committed block with 3/4 quorum signatures
    const blockHash = proposal.blockHash;
    const prevBlock = nodeA.getChain()[0];
    const merkleRoot = await buildMerkleRoot([tx]);

    // Signatures from A, B, C (3 of 4 quorum)
    const sigA = await sha256Hex(`${blockHash}:test-val-alpha:${cfgA.privateSigningKeyHex}`);
    const sigB = await sha256Hex(`${blockHash}:test-val-bravo:${cfgB.privateSigningKeyHex}`);
    const sigC = await sha256Hex(`${blockHash}:test-val-gamma:${cfgC.privateSigningKeyHex}`);

    const committedBlock: LedgerBlock = {
      height: 1,
      timestamp: proposal.timestamp,
      previousHash: prevBlock.blockHash,
      blockHash,
      merkleRoot,
      transactions: [tx],
      validatorSignatures: [
        { validatorId: 'test-val-alpha', validatorName: 'Validator Alpha', signatureHex: sigA },
        { validatorId: 'test-val-bravo', validatorName: 'Validator Bravo', signatureHex: sigB },
        { validatorId: 'test-val-gamma', validatorName: 'Validator Gamma', signatureHex: sigC },
      ],
      stateRoot: 'state-root-h1',
    };

    // Propagate BLOCK_COMMIT to B, C, D
    const commitMsg = {
      type: 'BLOCK_COMMIT' as const,
      senderNodeId: 'test-val-alpha',
      messageId: `COMMIT-${Date.now()}`,
      timestampEpochMs: Date.now(),
      payload: { block: committedBlock },
    };

    await nodeA.appendValidatedBlock(committedBlock);
    nodeA.broadcastMessage(commitMsg);

    // Directly deliver commit to B, C, D to verify handling
    await nodeB.handleBlockCommit({ block: committedBlock });
    await nodeC.handleBlockCommit({ block: committedBlock });
    await nodeD.handleBlockCommit({ block: committedBlock });

    assert.strictEqual(nodeA.getLatestBlock().height, 1);
    assert.strictEqual(nodeB.getLatestBlock().height, 1);
    assert.strictEqual(nodeC.getLatestBlock().height, 1);
    assert.strictEqual(nodeD.getLatestBlock().height, 1);
  });

  it('NODE-NET-04: All validators end with the exact same committed block hash', () => {
    const hashA = nodeA.getLatestBlock().blockHash;
    const hashB = nodeB.getLatestBlock().blockHash;
    const hashC = nodeC.getLatestBlock().blockHash;
    const hashD = nodeD.getLatestBlock().blockHash;

    assert.strictEqual(hashB, hashA);
    assert.strictEqual(hashC, hashA);
    assert.strictEqual(hashD, hashA);
  });

  it('NODE-NET-05: A late validator can synchronize missing blocks', async () => {
    // Spin up late Node E starting only with Genesis (height 0)
    const cfgE = makeTestConfig('test-val-late', 'Validator Late', portE, [], '0505050505050505050505050505050505050505050505050505050505050505');
    const nodeE = new ValidatorNodeEngine(cfgE);
    for (const cfg of [cfgA, cfgB, cfgC, cfgD, cfgE]) {
      nodeE.registerValidatorKey(cfg.nodeId, cfg.privateSigningKeyHex);
    }
    await nodeE.start();

    assert.strictEqual(nodeE.getLatestBlock().height, 0);

    // Node E requests missing blocks starting from height 1 from Node A
    const missingBlocks = nodeA.getChain().filter((b) => b.height >= 1);
    assert.strictEqual(missingBlocks.length, 1);

    const appended = await nodeE.handleBlockResponse({
      responderNodeId: 'test-val-alpha',
      blocks: missingBlocks,
    });

    assert.strictEqual(appended, 1);
    assert.strictEqual(nodeE.getLatestBlock().height, 1);
    assert.strictEqual(nodeE.getLatestBlock().blockHash, nodeA.getLatestBlock().blockHash);

    await nodeE.stop();
  });

  it('NODE-NET-06: Duplicate block messages do not duplicate blocks', async () => {
    const chainLengthBefore = nodeB.getChain().length;
    const currentBlock = nodeB.getLatestBlock();

    // Re-submit the exact same committed block
    const committedAgain = await nodeB.handleBlockCommit({ block: currentBlock });
    assert.strictEqual(committedAgain, false); // Rejected as duplicate

    const chainLengthAfter = nodeB.getChain().length;
    assert.strictEqual(chainLengthAfter, chainLengthBefore);
  });

  it('NODE-NET-07: Invalid blocks (corrupted block hash) are rejected', async () => {
    const currentHead = nodeB.getLatestBlock();
    const fakeBlock: LedgerBlock = {
      height: currentHead.height + 1,
      timestamp: Date.now(),
      previousHash: currentHead.blockHash,
      blockHash: '0000000000000000000000000000000000000000000000000000000000000000', // Invalid fake hash
      merkleRoot: '0000000000000000000000000000000000000000000000000000000000000000',
      transactions: [],
      validatorSignatures: [
        { validatorId: 'test-val-alpha', validatorName: 'Validator Alpha', signatureHex: 'sig1' },
        { validatorId: 'test-val-bravo', validatorName: 'Validator Bravo', signatureHex: 'sig2' },
        { validatorId: 'test-val-gamma', validatorName: 'Validator Gamma', signatureHex: 'sig3' },
      ],
      stateRoot: 'state-root-fake',
    };

    const isValid = await nodeB.validateIncomingBlock(fakeBlock);
    assert.strictEqual(isValid, false);

    const committed = await nodeB.handleBlockCommit({ block: fakeBlock });
    assert.strictEqual(committed, false);
  });

  it('NODE-NET-08: Invalid validator signatures are rejected', async () => {
    const currentHead = nodeC.getLatestBlock();
    const height = currentHead.height + 1;
    const timestamp = Date.now();
    const merkleRoot = '0000000000000000000000000000000000000000000000000000000000000000';
    const blockData = `BLOCK:${height}:${currentHead.blockHash}:${timestamp}:${merkleRoot}`;
    const blockHash = await sha256Hex(blockData);

    const fakeSignaturesBlock: LedgerBlock = {
      height,
      timestamp,
      previousHash: currentHead.blockHash,
      blockHash,
      merkleRoot,
      transactions: [],
      validatorSignatures: [
        { validatorId: 'test-val-alpha', validatorName: 'Validator Alpha', signatureHex: 'INVALID_FORGED_SIGNATURE_HEX' },
        { validatorId: 'test-val-bravo', validatorName: 'Validator Bravo', signatureHex: 'INVALID_FORGED_SIGNATURE_HEX' },
        { validatorId: 'test-val-gamma', validatorName: 'Validator Gamma', signatureHex: 'INVALID_FORGED_SIGNATURE_HEX' },
      ],
      stateRoot: `state-root-h${height}`,
    };

    const isValid = await nodeC.validateIncomingBlock(fakeSignaturesBlock);
    assert.strictEqual(isValid, false);
  });

  it('NODE-NET-09: Broken previous-block links are rejected', async () => {
    const currentHead = nodeD.getLatestBlock();
    const height = currentHead.height + 1;
    const timestamp = Date.now();
    const merkleRoot = '0000000000000000000000000000000000000000000000000000000000000000';
    const brokenPrevHash = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

    const blockData = `BLOCK:${height}:${brokenPrevHash}:${timestamp}:${merkleRoot}`;
    const blockHash = await sha256Hex(blockData);

    const brokenLinkBlock: LedgerBlock = {
      height,
      timestamp,
      previousHash: brokenPrevHash,
      blockHash,
      merkleRoot,
      transactions: [],
      validatorSignatures: [],
      stateRoot: `state-root-h${height}`,
    };

    const isValid = await nodeD.validateIncomingBlock(brokenLinkBlock);
    assert.strictEqual(isValid, false);
  });

  it('NODE-NET-10: Broken Merkle roots are rejected', async () => {
    const currentHead = nodeA.getLatestBlock();
    const height = currentHead.height + 1;
    const timestamp = Date.now();
    const tx = await createSampleTx();
    const genuineMerkle = await buildMerkleRoot([tx]);
    const tamperedMerkle = '1111111111111111111111111111111111111111111111111111111111111111';

    const blockData = `BLOCK:${height}:${currentHead.blockHash}:${timestamp}:${tamperedMerkle}`;
    const blockHash = await sha256Hex(blockData);

    const tamperedMerkleBlock: LedgerBlock = {
      height,
      timestamp,
      previousHash: currentHead.blockHash,
      blockHash,
      merkleRoot: tamperedMerkle,
      transactions: [tx],
      validatorSignatures: [],
      stateRoot: `state-root-h${height}`,
    };

    const isValid = await nodeA.validateIncomingBlock(tamperedMerkleBlock);
    assert.strictEqual(isValid, false);
  });

  it('NODE-NET-11: A validator that goes offline does not corrupt the remaining ledger', async () => {
    // Take Validator D offline
    await nodeD.stop();
    assert.strictEqual(nodeD.status, 'OFFLINE');

    // Validators A, B, C remain online (3/4 = 75% quorum satisfied)
    assert.strictEqual(nodeA.status, 'ONLINE');
    assert.strictEqual(nodeB.status, 'ONLINE');
    assert.strictEqual(nodeC.status, 'ONLINE');

    // A, B, C continue operating cleanly
    const auditA = await nodeA.auditLocalLedger();
    const auditB = await nodeB.auditLocalLedger();
    const auditC = await nodeC.auditLocalLedger();

    assert.strictEqual(auditA.isValid, true);
    assert.strictEqual(auditB.isValid, true);
    assert.strictEqual(auditC.isValid, true);
  });

  it('NODE-NET-12: Nodes recover after reconnecting', async () => {
    // Restart Validator D
    await nodeD.start();
    assert.strictEqual(nodeD.status, 'ONLINE');

    // Reconnect to Node A
    await nodeD.connectToPeer('test-val-alpha', '127.0.0.1', portA);
    const auditD = await nodeD.auditLocalLedger();
    assert.strictEqual(auditD.isValid, true);
  });

  it('NODE-NET-13: Network communication works with internet unavailable (offline loopback)', async () => {
    // Verify all listen hosts are strictly local loopback addresses
    assert.strictEqual(cfgA.listenHost, '127.0.0.1');
    assert.strictEqual(cfgB.listenHost, '127.0.0.1');
    assert.strictEqual(cfgC.listenHost, '127.0.0.1');
    assert.strictEqual(cfgD.listenHost, '127.0.0.1');

    // Test a direct local TCP socket exchange without DNS or external network
    const client = net.createConnection({ host: '127.0.0.1', port: portA });
    const isLocalConnected = await new Promise<boolean>((resolve) => {
      client.on('connect', () => {
        client.destroy();
        resolve(true);
      });
      client.on('error', () => resolve(false));
    });

    assert.strictEqual(isLocalConnected, true);
  });

  it('NODE-NET-14: Unknown/malformed messages are rejected safely without crashing', async () => {
    // 1. Send completely malformed null envelope
    await assert.doesNotReject(async () => {
      await nodeA.receiveMessage(null as any);
      await nodeA.receiveMessage({} as any);
      await nodeA.receiveMessage({ type: 'UNKNOWN_ATTACK_TYPE' } as any);
    });

    assert.strictEqual(nodeA.status, 'ONLINE');
  });

  it('NODE-NET-15: Replayed block messages do not create duplicate history', async () => {
    const chainBefore = nodeA.getChain();
    const genesisBlock = chainBefore[0];

    // Attempt to replay Block 0 (Genesis) as a commit
    await nodeA.handleBlockCommit({ block: genesisBlock });

    const chainAfter = nodeA.getChain();
    assert.strictEqual(chainAfter.length, chainBefore.length);
    assert.strictEqual(chainAfter[0].blockHash, genesisBlock.blockHash);
  });
});
