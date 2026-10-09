/**
 * Independent Validator Node Engine for Air-Gapped Permissioned DLT.
 *
 * Each ValidatorNode represents a completely autonomous logical node running
 * its own state machine, independent local ledger storage, independent transaction
 * pool, and cryptographic attestation engine.
 *
 * Core Guarantees:
 * - Independent process / runtime model
 * - Isolated persistent disk storage (.validator-data/<nodeId>/ledger.json)
 * - Zero blind trust: every block received over the network is independently audited
 * - Full deduplication: duplicate transactions, blocks, and messages are dropped
 * - Resilient quorum consensus: continues operating with 3/4 nodes online
 * - Offline LAN only: operates 100% disconnected from the internet
 */

import { DecryptionEvent, LedgerBlock, Recipient } from '../types';
import { sha256Hex, verifyMlDsa65, base64ToBytes, hexToBytes, canonicalizeJson } from '../crypto/pqc';
import { buildMerkleRoot, computeTransactionHash, createGenesisBlock } from '../ledger/dlt';
import { ValidatorNodeConfig } from './config';
import { NodeStorage } from './nodeStorage';
import { PeerNetworkTransport } from './peerConnection';
import {
  ValidatorNetworkMessage,
  ValidatorMessageType,
  TransactionProposalPayload,
  BlockProposalPayload,
  BlockAttestationPayload,
  BlockCommitPayload,
  LedgerHeadQueryPayload,
  LedgerHeadResponsePayload,
  BlockRequestPayload,
  BlockResponsePayload,
  NodeStatusPayload,
} from './types';

export class ValidatorNodeEngine {
  public readonly config: ValidatorNodeConfig;
  public readonly nodeId: string;
  public readonly name: string;
  public status: 'ONLINE' | 'VALIDATING' | 'SYNCED' | 'OFFLINE' = 'OFFLINE';

  private storage: NodeStorage;
  private network: PeerNetworkTransport;
  private localChain: LedgerBlock[] = [];
  private localMempool: DecryptionEvent[] = [];
  private registeredRecipients: Map<string, Recipient> = new Map();

  // Attestation accumulator for blocks currently under proposal: blockHash -> Map<validatorId, signatureHex>
  private pendingAttestations: Map<string, Map<string, { validatorName: string; signatureHex: string }>> = new Map();
  private pendingProposals: Map<string, BlockProposalPayload> = new Map();

  // Deduplication cache: messageId set, blockHash set, txId set
  private processedMessageIds: Set<string> = new Set();
  private committedBlockHashes: Set<string> = new Set();
  private seenTransactionIds: Set<string> = new Set();

  // Validator key registry for independent attestation verification
  private validatorKeys: Map<string, string> = new Map();

  // Anti-equivocation map: height -> blockHash
  private signedAttestationHeights: Map<number, string> = new Map();

  // Peer status cache
  private peerStatusTable: Map<string, NodeStatusPayload> = new Map();

  constructor(config: ValidatorNodeConfig) {
    this.config = config;
    this.nodeId = config.nodeId;
    this.name = config.name;
    this.storage = new NodeStorage(config.dataDir);
    this.network = new PeerNetworkTransport(config.nodeId, config.listenHost, config.listenPort);

    // Register initial cluster keys
    this.validatorKeys.set(config.nodeId, config.privateSigningKeyHex);

    // Register message handler
    this.network.on('message', (msg: ValidatorNetworkMessage) => {
      this.receiveMessage(msg);
    });

    this.network.on('peer_connected', ({ peerId }) => {
      this.sendStatusHeartbeat(peerId);
      this.queryPeerLedgerHead(peerId);
    });

    this.network.on('peer_disconnected', ({ peerId }) => {
      const existing = this.peerStatusTable.get(peerId);
      if (existing) {
        existing.status = 'OFFLINE';
      }
    });
  }

  // ==========================================
  // Lifecycle Management
  // ==========================================

  /**
   * Start the validator node:
   * 1. Loads local persistent ledger from isolated disk directory
   * 2. Initializes Genesis block if chain is empty
   * 3. Starts local TCP socket server
   * 4. Attempts connection to configured peers
   */
  public async start(): Promise<void> {
    // 1. Load local chain
    this.localChain = await this.storage.loadBlocks();
    if (this.localChain.length === 0) {
      const genesis = await createGenesisBlock();
      this.localChain = [genesis];
      await this.storage.saveBlocks(this.localChain);
    }

    // Populate deduplication sets
    for (const block of this.localChain) {
      this.committedBlockHashes.add(block.blockHash);
      for (const tx of block.transactions) {
        this.seenTransactionIds.add(tx.eventId);
        this.seenTransactionIds.add(tx.sessionId);
      }
    }

    // 2. Start TCP Server
    await this.network.startServer();
    this.status = 'ONLINE';

    // 3. Connect to configured peers
    await this.connectConfiguredPeers();

    // 4. Broadcast initial status
    this.broadcastStatus();
  }

  /**
   * Stop the validator node and close all sockets and servers.
   */
  public async stop(): Promise<void> {
    this.status = 'OFFLINE';
    await this.network.stop();
  }

  /**
   * Connect to all configured peers in the cluster.
   */
  public async connectConfiguredPeers(): Promise<void> {
    for (const peer of this.config.peers) {
      if (peer.nodeId !== this.nodeId) {
        await this.network.connectToPeer(peer.nodeId, peer.host, peer.port);
      }
    }
  }

  // ==========================================
  // Identity and Registry
  // ==========================================

  public registerRecipient(recipient: Recipient): void {
    this.registeredRecipients.set(recipient.id, recipient);
  }

  public getRecipient(id: string): Recipient | undefined {
    return this.registeredRecipients.get(id);
  }

  // ==========================================
  // State Inspection
  // ==========================================

  public getChain(): LedgerBlock[] {
    return JSON.parse(JSON.stringify(this.localChain));
  }

  public getLatestBlock(): LedgerBlock {
    return this.localChain[this.localChain.length - 1];
  }

  public getMempool(): DecryptionEvent[] {
    return JSON.parse(JSON.stringify(this.localMempool));
  }

  public getPeerStatusTable(): NodeStatusPayload[] {
    return Array.from(this.peerStatusTable.values());
  }

  public getConnectedPeerIds(): string[] {
    return this.network.getConnectedPeers();
  }

  public getLedgerHead(): { height: number; headBlockHash: string; totalTransactions: number } {
    const head = this.getLatestBlock();
    let totalTx = 0;
    for (const b of this.localChain) totalTx += b.transactions.length;
    return {
      height: head.height,
      headBlockHash: head.blockHash,
      totalTransactions: totalTx,
    };
  }

  // ==========================================
  // P2P Communication & Message Routing
  // ==========================================

  public connectToPeer(peerId: string, host: string, port: number): Promise<boolean> {
    return this.network.connectToPeer(peerId, host, port);
  }

  public disconnectPeer(peerId: string): void {
    this.network.disconnectPeer(peerId);
  }

  public broadcastMessage(message: ValidatorNetworkMessage): number {
    return this.network.broadcastMessage(message);
  }

  public sendMessage(peerId: string, message: ValidatorNetworkMessage): boolean {
    return this.network.sendMessage(peerId, message);
  }

  private createMessage<T>(type: ValidatorMessageType, payload: T, targetNodeId?: string): ValidatorNetworkMessage<T> {
    return {
      type,
      senderNodeId: this.nodeId,
      targetNodeId,
      messageId: `MSG-${this.nodeId}-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
      timestampEpochMs: Date.now(),
      payload,
    };
  }

  /**
   * Main message router for incoming network frames.
   * Enforces message validation, deduplication, and safe failure handling.
   */
  public async receiveMessage(msg: ValidatorNetworkMessage): Promise<void> {
    // 1. Validate envelope structure
    if (!msg || typeof msg !== 'object' || !msg.type || !msg.senderNodeId || !msg.messageId) {
      console.warn(`[${this.nodeId}] Dropping malformed envelope`);
      return;
    }

    // 2. Reject messages targeted to other nodes
    if (msg.targetNodeId && msg.targetNodeId !== this.nodeId) {
      return;
    }

    // 3. Deduplicate message ID
    if (this.processedMessageIds.has(msg.messageId)) {
      return;
    }
    this.processedMessageIds.add(msg.messageId);

    // Keep deduplication set bounded to 50,000 items
    if (this.processedMessageIds.size > 50000) {
      const first = Array.from(this.processedMessageIds).slice(0, 10000);
      for (const id of first) this.processedMessageIds.delete(id);
    }

    try {
      switch (msg.type) {
        case 'TRANSACTION_PROPOSAL':
          await this.handleTransactionProposal(msg.payload as TransactionProposalPayload);
          break;

        case 'BLOCK_PROPOSAL':
          await this.handleBlockProposal(msg.payload as BlockProposalPayload);
          break;

        case 'BLOCK_ATTESTATION':
          await this.handleBlockAttestation(msg.payload as BlockAttestationPayload);
          break;

        case 'BLOCK_COMMIT':
          await this.handleBlockCommit(msg.payload as BlockCommitPayload);
          break;

        case 'LEDGER_HEAD_QUERY':
          await this.handleLedgerHeadQuery(msg.senderNodeId);
          break;

        case 'LEDGER_HEAD_RESPONSE':
          await this.handleLedgerHeadResponse(msg.payload as LedgerHeadResponsePayload, msg.senderNodeId);
          break;

        case 'BLOCK_REQUEST':
          await this.handleBlockRequest(msg.payload as BlockRequestPayload, msg.senderNodeId);
          break;

        case 'BLOCK_RESPONSE':
          await this.handleBlockResponse(msg.payload as BlockResponsePayload);
          break;

        case 'NODE_STATUS':
          this.handleNodeStatus(msg.payload as NodeStatusPayload);
          break;

        default:
          console.warn(`[${this.nodeId}] Unknown message type: ${(msg as any).type}`);
      }
    } catch (err: any) {
      console.warn(`[${this.nodeId}] Error processing message ${msg.type}:`, err.message);
    }
  }

  // ==========================================
  // Transaction Processing
  // ==========================================

  /**
   * Submit a Decryption Event to this node.
   * Validates ML-DSA-65 post-quantum signature, checks replay, adds to local mempool,
   * and propagates TRANSACTION_PROPOSAL to peers.
   */
  public async submitTransaction(tx: DecryptionEvent): Promise<{ success: boolean; error?: string }> {
    // 1. Check duplicate / replay
    if (this.seenTransactionIds.has(tx.eventId) || this.seenTransactionIds.has(tx.sessionId)) {
      return {
        success: false,
        error: `ReplayAttackRejected: Event ${tx.eventId} is already recorded in mempool or chain.`,
      };
    }

    // 2. Validate ML-DSA-65 signature if recipient is known
    const recipient = this.registeredRecipients.get(tx.recipientId);
    if (recipient) {
      const canonical = canonicalizeJson({
        eventId: tx.eventId,
        documentId: tx.documentId,
        documentHashSha256: tx.documentHashSha256,
        packageHashSha256: tx.packageHashSha256,
        recipientId: tx.recipientId,
        recipientPubkeyFingerprint: tx.recipientPubkeyFingerprint,
        sessionId: tx.sessionId,
        watermarkId: tx.watermarkId,
        watermarkCommitment: tx.watermarkCommitment,
        timestampEpochMs: tx.timestampEpochMs,
      });

      const msgBytes = new TextEncoder().encode(canonical);
      const sigBytes = base64ToBytes(tx.recipientSignatureBase64);
      const pubKeyBytes = hexToBytes(recipient.keys.dsaPublicKeyHex);

      const isValid = verifyMlDsa65(sigBytes, msgBytes, pubKeyBytes);
      if (!isValid) {
        return {
          success: false,
          error: `Cryptographic validation rejected: Invalid ML-DSA-65 signature on tx ${tx.eventId}.`,
        };
      }
    }

    // 3. Add to local mempool
    tx.status = 'MEMPOOL';
    this.localMempool.push(tx);
    this.seenTransactionIds.add(tx.eventId);
    this.seenTransactionIds.add(tx.sessionId);

    // 4. Propagate to peers
    const proposalMsg = this.createMessage<TransactionProposalPayload>('TRANSACTION_PROPOSAL', {
      transaction: tx,
    });
    this.broadcastMessage(proposalMsg);

    return { success: true };
  }

  private async handleTransactionProposal(payload: TransactionProposalPayload): Promise<void> {
    if (!payload || !payload.transaction) return;
    const tx = payload.transaction;

    // Check duplicate
    if (this.seenTransactionIds.has(tx.eventId) || this.seenTransactionIds.has(tx.sessionId)) {
      return;
    }

    // Validate ML-DSA-65 signature if recipient is registered
    const recipient = this.registeredRecipients.get(tx.recipientId);
    if (recipient) {
      const canonical = canonicalizeJson({
        eventId: tx.eventId,
        documentId: tx.documentId,
        documentHashSha256: tx.documentHashSha256,
        packageHashSha256: tx.packageHashSha256,
        recipientId: tx.recipientId,
        recipientPubkeyFingerprint: tx.recipientPubkeyFingerprint,
        sessionId: tx.sessionId,
        watermarkId: tx.watermarkId,
        watermarkCommitment: tx.watermarkCommitment,
        timestampEpochMs: tx.timestampEpochMs,
      });
      const msgBytes = new TextEncoder().encode(canonical);
      const sigBytes = base64ToBytes(tx.recipientSignatureBase64);
      const pubKeyBytes = hexToBytes(recipient.keys.dsaPublicKeyHex);
      if (!verifyMlDsa65(sigBytes, msgBytes, pubKeyBytes)) {
        console.warn(`[${this.nodeId}] Rejected invalid transaction proposal: ${tx.eventId}`);
        return;
      }
    }

    tx.status = 'MEMPOOL';
    this.localMempool.push(tx);
    this.seenTransactionIds.add(tx.eventId);
    this.seenTransactionIds.add(tx.sessionId);
  }

  // ==========================================
  // Block Proposal & Consensus Flow
  // ==========================================

  /**
   * Propose a new block from transactions in local mempool.
   * Broadcasts BLOCK_PROPOSAL to all cluster peers.
   */
  public async proposeBlock(): Promise<BlockProposalPayload | null> {
    if (this.localMempool.length === 0) {
      return null;
    }

    const previousBlock = this.getLatestBlock();
    const height = previousBlock.height + 1;
    const timestamp = Date.now();
    const transactions = [...this.localMempool];

    // Compute Merkle Root
    const merkleRoot = await buildMerkleRoot(transactions);

    // Compute Block Hash: SHA-256(height + prevHash + timestamp + merkleRoot)
    const blockData = `BLOCK:${height}:${previousBlock.blockHash}:${timestamp}:${merkleRoot}`;
    const blockHash = await sha256Hex(blockData);

    const proposal: BlockProposalPayload = {
      height,
      timestamp,
      previousHash: previousBlock.blockHash,
      blockHash,
      merkleRoot,
      transactions,
      proposerNodeId: this.nodeId,
    };

    // Self-attest to proposal
    const selfAttestation = await this.signBlockAttestation(blockHash);
    const attestations = new Map<string, { validatorName: string; signatureHex: string }>();
    attestations.set(this.nodeId, {
      validatorName: this.name,
      signatureHex: selfAttestation,
    });
    this.pendingAttestations.set(blockHash, attestations);
    this.pendingProposals.set(blockHash, proposal);

    // Broadcast proposal to peers
    const msg = this.createMessage<BlockProposalPayload>('BLOCK_PROPOSAL', proposal);
    this.broadcastMessage(msg);

    return proposal;
  }

  /**
   * Handle incoming BLOCK_PROPOSAL from another validator.
   * Independently audits:
   * - Height continuity (height === head + 1)
   * - Previous block hash link
   * - Merkle root computation over transactions
   * - Block hash computation
   * - Transaction signatures
   *
   * If valid: signs attestation and replies to proposer.
   */
  private async handleBlockProposal(proposal: BlockProposalPayload): Promise<void> {
    if (!proposal || !proposal.blockHash) return;

    // Check duplicate
    if (this.committedBlockHashes.has(proposal.blockHash)) {
      return;
    }

    const latestBlock = this.getLatestBlock();

    // 1. Height check
    if (proposal.height !== latestBlock.height + 1) {
      console.warn(`[${this.nodeId}] Rejected proposal: invalid height ${proposal.height} (expected ${latestBlock.height + 1})`);
      return;
    }

    // 2. Previous Hash Link check
    if (proposal.previousHash !== latestBlock.blockHash) {
      console.warn(`[${this.nodeId}] Rejected proposal: previousHash mismatch`);
      return;
    }

    // 3. Merkle Root validation
    const computedMerkle = await buildMerkleRoot(proposal.transactions);
    if (computedMerkle !== proposal.merkleRoot) {
      console.warn(`[${this.nodeId}] Rejected proposal: Merkle root mismatch`);
      return;
    }

    // 4. Block Hash recalculation check
    const blockData = `BLOCK:${proposal.height}:${proposal.previousHash}:${proposal.timestamp}:${proposal.merkleRoot}`;
    const computedHash = await sha256Hex(blockData);
    if (computedHash !== proposal.blockHash) {
      console.warn(`[${this.nodeId}] Rejected proposal: block hash mismatch`);
      return;
    }

    // 5. Audit transactions
    for (const tx of proposal.transactions) {
      const recipient = this.registeredRecipients.get(tx.recipientId);
      if (recipient) {
        const canonical = canonicalizeJson({
          eventId: tx.eventId,
          documentId: tx.documentId,
          documentHashSha256: tx.documentHashSha256,
          packageHashSha256: tx.packageHashSha256,
          recipientId: tx.recipientId,
          recipientPubkeyFingerprint: tx.recipientPubkeyFingerprint,
          sessionId: tx.sessionId,
          watermarkId: tx.watermarkId,
          watermarkCommitment: tx.watermarkCommitment,
          timestampEpochMs: tx.timestampEpochMs,
        });
        const msgBytes = new TextEncoder().encode(canonical);
        const sigBytes = base64ToBytes(tx.recipientSignatureBase64);
        const pubKeyBytes = hexToBytes(recipient.keys.dsaPublicKeyHex);
        if (!verifyMlDsa65(sigBytes, msgBytes, pubKeyBytes)) {
          console.warn(`[${this.nodeId}] Rejected proposal: invalid recipient signature on ${tx.eventId}`);
          return;
        }
      }
    }

    // Anti-Equivocation check: An honest validator never attests to two different blocks at the same height
    if (this.signedAttestationHeights.has(proposal.height)) {
      const signedHash = this.signedAttestationHeights.get(proposal.height);
      if (signedHash !== proposal.blockHash) {
        console.warn(`[${this.nodeId}] ConflictingBlockRejected: Already attested to block ${signedHash} at height ${proposal.height}. Rejecting conflicting proposal ${proposal.blockHash}.`);
        return;
      }
    }

    // Proposal is valid: create cryptographic attestation signature
    const signatureHex = await this.signBlockAttestation(proposal.blockHash);
    this.signedAttestationHeights.set(proposal.height, proposal.blockHash);

    const attestation: BlockAttestationPayload = {
      blockHash: proposal.blockHash,
      height: proposal.height,
      validatorId: this.nodeId,
      validatorName: this.name,
      signatureHex,
    };

    // Store in our own attestation table
    if (!this.pendingAttestations.has(proposal.blockHash)) {
      this.pendingAttestations.set(proposal.blockHash, new Map());
    }
    this.pendingAttestations.get(proposal.blockHash)!.set(this.nodeId, {
      validatorName: this.name,
      signatureHex,
    });
    this.pendingProposals.set(proposal.blockHash, proposal);

    // Send attestation back to proposer (or broadcast)
    const attMsg = this.createMessage<BlockAttestationPayload>('BLOCK_ATTESTATION', attestation, proposal.proposerNodeId);
    this.network.sendMessage(proposal.proposerNodeId, attMsg);
  }

  /**
   * Handle incoming BLOCK_ATTESTATION from another validator.
   * When quorum is reached (e.g. 3 of 4), assemble committed block and broadcast BLOCK_COMMIT.
   */
  private async handleBlockAttestation(payload: BlockAttestationPayload): Promise<void> {
    if (!payload || !payload.blockHash || !payload.validatorId) return;

    // Verify attestation signature
    const expectedAttestation = await this.computeExpectedAttestation(payload.blockHash, payload.validatorId);
    if (expectedAttestation !== payload.signatureHex) {
      console.warn(`[${this.nodeId}] Rejected invalid attestation from ${payload.validatorId}`);
      return;
    }

    let map = this.pendingAttestations.get(payload.blockHash);
    if (!map) {
      map = new Map();
      this.pendingAttestations.set(payload.blockHash, map);
    }
    map.set(payload.validatorId, {
      validatorName: payload.validatorName,
      signatureHex: payload.signatureHex,
    });

    // Check if quorum reached
    const proposal = this.pendingProposals.get(payload.blockHash);
    if (proposal && map.size >= this.config.quorumRequired) {
      // Assemble committed block with quorum validator signatures
      const validatorSignatures = Array.from(map.entries()).map(([vId, info]) => ({
        validatorId: vId,
        validatorName: info.validatorName,
        signatureHex: info.signatureHex,
      }));

      for (const tx of proposal.transactions) {
        tx.status = 'COMMITTED';
        tx.blockHeight = proposal.height;
        tx.txHash = await computeTransactionHash(tx);
      }

      const committedBlock: LedgerBlock = {
        height: proposal.height,
        timestamp: proposal.timestamp,
        previousHash: proposal.previousHash,
        blockHash: proposal.blockHash,
        merkleRoot: proposal.merkleRoot,
        transactions: proposal.transactions,
        validatorSignatures,
        stateRoot: `state-root-h${proposal.height}`,
      };

      // Commit locally
      await this.commitBlockLocally(committedBlock);

      // Broadcast BLOCK_COMMIT to network
      const commitMsg = this.createMessage<BlockCommitPayload>('BLOCK_COMMIT', {
        block: committedBlock,
      });
      this.broadcastMessage(commitMsg);

      // Clean up pending
      this.pendingProposals.delete(payload.blockHash);
      this.pendingAttestations.delete(payload.blockHash);
    }
  }

  /**
   * Handle incoming BLOCK_COMMIT from another validator.
   * Performs full independent validation before persisting to local storage.
   */
  public async handleBlockCommit(payload: BlockCommitPayload): Promise<boolean> {
    if (!payload || !payload.block) return false;
    const block = payload.block;

    // Duplicate check
    if (this.committedBlockHashes.has(block.blockHash)) {
      return false; // Already committed, safe no-op
    }

    // 1. Independent validation of the incoming block
    const isValid = await this.validateIncomingBlock(block);
    if (!isValid) {
      console.warn(`[${this.nodeId}] Rejected BLOCK_COMMIT for Block #${block.height}: validation failed`);
      return false;
    }

    // 2. Append validated block and persist
    await this.appendValidatedBlock(block);
    return true;
  }

  // ==========================================
  // Ledger Synchronization / Catch-Up Engine
  // ==========================================

  /**
   * Query a peer's ledger head to detect if local node is behind.
   */
  public queryPeerLedgerHead(peerId: string): void {
    const msg = this.createMessage<LedgerHeadQueryPayload>('LEDGER_HEAD_QUERY', {
      queryFromNodeId: this.nodeId,
    }, peerId);
    this.network.sendMessage(peerId, msg);
  }

  private handleLedgerHeadQuery(requestorNodeId: string): void {
    const head = this.getLedgerHead();
    const response: LedgerHeadResponsePayload = {
      nodeId: this.nodeId,
      currentHeight: head.height,
      headBlockHash: head.headBlockHash,
      totalTransactions: head.totalTransactions,
      timestamp: Date.now(),
    };
    const msg = this.createMessage<LedgerHeadResponsePayload>('LEDGER_HEAD_RESPONSE', response, requestorNodeId);
    this.network.sendMessage(requestorNodeId, msg);
  }

  private async handleLedgerHeadResponse(response: LedgerHeadResponsePayload, peerId: string): Promise<void> {
    const localHead = this.getLatestBlock();
    if (response.currentHeight > localHead.height) {
      // We are behind! Request missing blocks
      this.requestMissingBlocks(localHead.height + 1, peerId);
    }
  }

  /**
   * Request missing blocks from a peer starting from a given height.
   */
  public requestMissingBlocks(fromHeight: number, peerId: string): void {
    const req: BlockRequestPayload = {
      requestorNodeId: this.nodeId,
      fromHeight,
    };
    const msg = this.createMessage<BlockRequestPayload>('BLOCK_REQUEST', req, peerId);
    this.network.sendMessage(peerId, msg);
  }

  private handleBlockRequest(payload: BlockRequestPayload, requestorNodeId: string): void {
    if (!payload || typeof payload.fromHeight !== 'number') return;

    const blocksToSend = this.localChain.filter((b) => b.height >= payload.fromHeight);
    const response: BlockResponsePayload = {
      responderNodeId: this.nodeId,
      blocks: blocksToSend,
    };
    const msg = this.createMessage<BlockResponsePayload>('BLOCK_RESPONSE', response, requestorNodeId);
    this.network.sendMessage(requestorNodeId, msg);
  }

  /**
   * Receive and process missing blocks from a peer.
   * Audits each block in sequence before persistence.
   */
  public async handleBlockResponse(payload: BlockResponsePayload): Promise<number> {
    if (!payload || !Array.isArray(payload.blocks)) return 0;
    let appendedCount = 0;

    for (const block of payload.blocks) {
      // Check if already committed
      if (this.committedBlockHashes.has(block.blockHash)) {
        continue;
      }

      const isValid = await this.validateIncomingBlock(block);
      if (isValid) {
        await this.appendValidatedBlock(block);
        appendedCount++;
      } else {
        console.warn(`[${this.nodeId}] Synchronization halted: block #${block.height} failed independent verification`);
        break;
      }
    }

    return appendedCount;
  }

  /**
   * Independent verification of an incoming block before storage.
   * Checks:
   * - Block height sequence
   * - Previous block hash link
   * - Merkle root calculation
   * - Block hash calculation
   * - Validator quorum signatures
   */
  public async validateIncomingBlock(block: LedgerBlock): Promise<boolean> {
    if (!block || typeof block.height !== 'number') return false;

    const latest = this.getLatestBlock();

    // 1. Height continuity check
    if (block.height !== latest.height + 1) {
      return false;
    }

    // 2. Previous Hash Link check
    if (block.previousHash !== latest.blockHash) {
      return false;
    }

    // 3. Merkle Root validation
    const computedMerkle = await buildMerkleRoot(block.transactions);
    if (computedMerkle !== block.merkleRoot) {
      return false;
    }

    // 4. Block Hash calculation check
    const blockData = `BLOCK:${block.height}:${block.previousHash}:${block.timestamp}:${block.merkleRoot}`;
    const computedHash = await sha256Hex(blockData);
    if (computedHash !== block.blockHash) {
      return false;
    }

    // 5. Validator quorum signatures check
    if (!block.validatorSignatures || block.validatorSignatures.length < this.config.quorumRequired) {
      return false;
    }

    // Verify each validator attestation signature
    for (const sig of block.validatorSignatures) {
      const expected = await this.computeExpectedAttestation(block.blockHash, sig.validatorId);
      if (expected !== sig.signatureHex) {
        return false;
      }
    }

    return true;
  }

  /**
   * Commit a fully validated block to the local chain and disk storage.
   */
  public async appendValidatedBlock(block: LedgerBlock): Promise<void> {
    if (this.committedBlockHashes.has(block.blockHash)) {
      return;
    }

    const clonedBlock: LedgerBlock = JSON.parse(JSON.stringify(block));
    this.localChain.push(clonedBlock);
    this.committedBlockHashes.add(clonedBlock.blockHash);

    // Evict transactions from mempool and record in seen set
    const committedTxIds = new Set(clonedBlock.transactions.map((tx) => tx.eventId));
    this.localMempool = this.localMempool.filter((tx) => !committedTxIds.has(tx.eventId));
    for (const tx of clonedBlock.transactions) {
      this.seenTransactionIds.add(tx.eventId);
      this.seenTransactionIds.add(tx.sessionId);
    }

    // Persist to isolated local storage
    await this.storage.saveBlocks(this.localChain);
  }

  private async commitBlockLocally(block: LedgerBlock): Promise<void> {
    await this.appendValidatedBlock(block);
  }

  // ==========================================
  // Cryptographic Attestation Helpers
  // ==========================================

  public registerValidatorKey(validatorId: string, keyHex: string): void {
    this.validatorKeys.set(validatorId, keyHex);
  }

  private async signBlockAttestation(blockHash: string): Promise<string> {
    const data = `${blockHash}:${this.nodeId}:${this.config.privateSigningKeyHex}`;
    return await sha256Hex(data);
  }

  private async computeExpectedAttestation(blockHash: string, validatorId: string): Promise<string> {
    // Check local registry first
    let keyHex = this.validatorKeys.get(validatorId);
    if (!keyHex) {
      const clusterConfig = this.config.peers.find((p) => p.nodeId === validatorId);
      if (clusterConfig) {
        keyHex = this.config.privateSigningKeyHex;
      }
      const remoteConfig = (await import('./config')).CLUSTER_VALIDATOR_CONFIGS[validatorId];
      if (remoteConfig) {
        keyHex = remoteConfig.privateSigningKeyHex;
      }
    }
    if (!keyHex) {
      keyHex = this.config.privateSigningKeyHex;
    }
    const data = `${blockHash}:${validatorId}:${keyHex}`;
    return await sha256Hex(data);
  }

  // ==========================================
  // Heartbeat & Status
  // ==========================================

  public broadcastStatus(): void {
    const head = this.getLatestBlock();
    const statusPayload: NodeStatusPayload = {
      nodeId: this.nodeId,
      name: this.name,
      status: this.status,
      currentHeight: head.height,
      headBlockHash: head.blockHash,
      listenPort: this.config.listenPort,
      connectedPeerCount: this.network.getConnectedPeers().length,
      timestamp: Date.now(),
    };
    const msg = this.createMessage<NodeStatusPayload>('NODE_STATUS', statusPayload);
    this.broadcastMessage(msg);
  }

  public sendStatusHeartbeat(peerId: string): void {
    const head = this.getLatestBlock();
    const statusPayload: NodeStatusPayload = {
      nodeId: this.nodeId,
      name: this.name,
      status: this.status,
      currentHeight: head.height,
      headBlockHash: head.blockHash,
      listenPort: this.config.listenPort,
      connectedPeerCount: this.network.getConnectedPeers().length,
      timestamp: Date.now(),
    };
    const msg = this.createMessage<NodeStatusPayload>('NODE_STATUS', statusPayload, peerId);
    this.network.sendMessage(peerId, msg);
  }

  private handleNodeStatus(payload: NodeStatusPayload): void {
    if (!payload || !payload.nodeId) return;
    this.peerStatusTable.set(payload.nodeId, payload);
  }

  /**
   * Verify the integrity of this node's local ledger from Genesis to Head.
   */
  public async auditLocalLedger(): Promise<{ isValid: boolean; reason?: string }> {
    for (let i = 1; i < this.localChain.length; i++) {
      const prev = this.localChain[i - 1];
      const curr = this.localChain[i];

      if (curr.previousHash !== prev.blockHash) {
        return { isValid: false, reason: `Broken chain link at height ${curr.height}` };
      }
      const merkle = await buildMerkleRoot(curr.transactions);
      if (curr.merkleRoot !== merkle) {
        return { isValid: false, reason: `Merkle root mismatch at height ${curr.height}` };
      }
      const data = `BLOCK:${curr.height}:${curr.previousHash}:${curr.timestamp}:${curr.merkleRoot}`;
      const hash = await sha256Hex(data);
      if (curr.blockHash !== hash) {
        return { isValid: false, reason: `Block hash mismatch at height ${curr.height}` };
      }
      if (!curr.validatorSignatures || curr.validatorSignatures.length < this.config.quorumRequired) {
        return { isValid: false, reason: `Insufficient validator quorum at height ${curr.height}` };
      }
    }
    return { isValid: true };
  }

  /**
   * Simulate administrative or historical tampering on a local block.
   */
  public simulateHistoricalTamper(blockHeight: number, fakeRecipientId: string): boolean {
    const block = this.localChain.find((b) => b.height === blockHeight);
    if (!block || block.transactions.length === 0) return false;
    block.transactions[0].recipientId = fakeRecipientId;
    block.transactions[0].recipientName = `Tampered: ${fakeRecipientId}`;
    return true;
  }

  /**
   * Recover local ledger by requesting and independently auditing canonical blocks from a healthy peer.
   */
  public async recoverFromPeer(peer: ValidatorNodeEngine): Promise<{ success: boolean; blocksRecovered: number; headHash: string }> {
    const canonicalChain = peer.getChain();

    // Independently audit every single block in the canonical chain before adopting
    for (let i = 1; i < canonicalChain.length; i++) {
      const prev = canonicalChain[i - 1];
      const curr = canonicalChain[i];

      if (curr.previousHash !== prev.blockHash) {
        return { success: false, blocksRecovered: 0, headHash: this.getLatestBlock().blockHash };
      }
      const merkle = await buildMerkleRoot(curr.transactions);
      if (curr.merkleRoot !== merkle) {
        return { success: false, blocksRecovered: 0, headHash: this.getLatestBlock().blockHash };
      }
      if (!curr.validatorSignatures || curr.validatorSignatures.length < this.config.quorumRequired) {
        return { success: false, blocksRecovered: 0, headHash: this.getLatestBlock().blockHash };
      }
    }

    // Rebuild local isolated state
    this.localChain = JSON.parse(JSON.stringify(canonicalChain));
    this.committedBlockHashes.clear();
    for (const b of this.localChain) {
      this.committedBlockHashes.add(b.blockHash);
    }
    await this.storage.saveBlocks(this.localChain);

    return {
      success: true,
      blocksRecovered: this.localChain.length - 1,
      headHash: this.getLatestBlock().blockHash,
    };
  }
}
