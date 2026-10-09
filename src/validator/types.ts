/**
 * Validator Network Protocol Types and Message Definitions.
 *
 * All messages exchanged across the offline local network transport are
 * strongly-typed, schema-validated, and framed to prevent buffer overrun.
 */

import { DecryptionEvent, LedgerBlock } from '../types';

export type ValidatorMessageType =
  | 'TRANSACTION_PROPOSAL'
  | 'BLOCK_PROPOSAL'
  | 'BLOCK_ATTESTATION'
  | 'BLOCK_COMMIT'
  | 'LEDGER_HEAD_QUERY'
  | 'LEDGER_HEAD_RESPONSE'
  | 'BLOCK_REQUEST'
  | 'BLOCK_RESPONSE'
  | 'NODE_STATUS';

export interface ValidatorNetworkMessage<T = any> {
  type: ValidatorMessageType;
  senderNodeId: string;
  targetNodeId?: string; // Optional: empty means broadcast to all connected peers
  messageId: string;
  timestampEpochMs: number;
  payload: T;
  signatureHex?: string; // Validator attestation signature over canonical payload
}

// Payload: TRANSACTION_PROPOSAL
export interface TransactionProposalPayload {
  transaction: DecryptionEvent;
}

// Payload: BLOCK_PROPOSAL
export interface BlockProposalPayload {
  height: number;
  timestamp: number;
  previousHash: string;
  blockHash: string;
  merkleRoot: string;
  transactions: DecryptionEvent[];
  proposerNodeId: string;
}

// Payload: BLOCK_ATTESTATION (validator signature in response to BLOCK_PROPOSAL)
export interface BlockAttestationPayload {
  blockHash: string;
  height: number;
  validatorId: string;
  validatorName: string;
  signatureHex: string;
}

// Payload: BLOCK_COMMIT (committed block with gathered quorum signatures)
export interface BlockCommitPayload {
  block: LedgerBlock;
}

// Payload: LEDGER_HEAD_QUERY
export interface LedgerHeadQueryPayload {
  queryFromNodeId: string;
}

// Payload: LEDGER_HEAD_RESPONSE
export interface LedgerHeadResponsePayload {
  nodeId: string;
  currentHeight: number;
  headBlockHash: string;
  totalTransactions: number;
  timestamp: number;
}

// Payload: BLOCK_REQUEST (catch up synchronization)
export interface BlockRequestPayload {
  requestorNodeId: string;
  fromHeight: number; // inclusive
  toHeight?: number;  // optional upper bound
}

// Payload: BLOCK_RESPONSE (catch up blocks)
export interface BlockResponsePayload {
  responderNodeId: string;
  blocks: LedgerBlock[];
}

// Payload: NODE_STATUS (heartbeat / connection handshake)
export interface NodeStatusPayload {
  nodeId: string;
  name: string;
  status: 'ONLINE' | 'VALIDATING' | 'SYNCED' | 'OFFLINE';
  currentHeight: number;
  headBlockHash: string;
  listenPort: number;
  connectedPeerCount: number;
  timestamp: number;
}
