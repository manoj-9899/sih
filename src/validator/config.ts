/**
 * Validator Node Configuration for Air-Gapped Multi-Node Cluster.
 *
 * Each validator node has:
 * - Unique Node ID and Human-Readable Name
 * - Isolated local data directory
 * - Dedicated TCP socket port for peer-to-peer replication
 * - Dedicated HTTP port for local query/health inspection
 * - Independent cryptographic signing key for block attestation
 * - Peer connection address table
 * - Quorum parameters (e.g., 3-of-4 quorum = 75%)
 */

import path from 'node:path';

export interface ValidatorPeerConfig {
  nodeId: string;
  host: string;
  port: number;
}

export interface ValidatorNodeConfig {
  nodeId: string;
  name: string;
  role: string;
  location: string;
  listenHost: string;
  listenPort: number; // TCP socket for P2P replication
  httpPort: number;   // HTTP port for local health / inspection
  dataDir: string;    // Isolated directory for local ledger storage
  peers: ValidatorPeerConfig[];
  quorumRequired: number; // e.g., 3 out of 4 (>= 75%)
  publicVerificationKeyHex: string;
  privateSigningKeyHex: string;
}

// Fixed deterministic post-quantum / attestation keypairs for the 4 offline cluster nodes
export const CLUSTER_VALIDATOR_CONFIGS: Record<string, ValidatorNodeConfig> = {
  'val-alpha-01': {
    nodeId: 'val-alpha-01',
    name: 'Validator Alpha',
    role: 'Primary Consensus Node',
    location: 'Primary Enclave',
    listenHost: '127.0.0.1',
    listenPort: 7001,
    httpPort: 8001,
    dataDir: path.resolve(process.cwd(), '.validator-data/val-alpha-01'),
    peers: [
      { nodeId: 'val-bravo-02', host: '127.0.0.1', port: 7002 },
      { nodeId: 'val-gamma-03', host: '127.0.0.1', port: 7003 },
      { nodeId: 'val-delta-04', host: '127.0.0.1', port: 7004 },
    ],
    quorumRequired: 3,
    publicVerificationKeyHex: '7a9f8b1c4d2e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
    privateSigningKeyHex: '0101010101010101010101010101010101010101010101010101010101010101',
  },
  'val-bravo-02': {
    nodeId: 'val-bravo-02',
    name: 'Validator Bravo',
    role: 'Secondary Verification Node',
    location: 'Secondary Enclave',
    listenHost: '127.0.0.1',
    listenPort: 7002,
    httpPort: 8002,
    dataDir: path.resolve(process.cwd(), '.validator-data/val-bravo-02'),
    peers: [
      { nodeId: 'val-alpha-01', host: '127.0.0.1', port: 7001 },
      { nodeId: 'val-gamma-03', host: '127.0.0.1', port: 7003 },
      { nodeId: 'val-delta-04', host: '127.0.0.1', port: 7004 },
    ],
    quorumRequired: 3,
    publicVerificationKeyHex: '8b0a9c2d5e3f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1c',
    privateSigningKeyHex: '0202020202020202020202020202020202020202020202020202020202020202',
  },
  'val-gamma-03': {
    nodeId: 'val-gamma-03',
    name: 'Validator Gamma',
    role: 'Audit Authority Node',
    location: 'Audit Enclave',
    listenHost: '127.0.0.1',
    listenPort: 7003,
    httpPort: 8003,
    dataDir: path.resolve(process.cwd(), '.validator-data/val-gamma-03'),
    peers: [
      { nodeId: 'val-alpha-01', host: '127.0.0.1', port: 7001 },
      { nodeId: 'val-bravo-02', host: '127.0.0.1', port: 7002 },
      { nodeId: 'val-delta-04', host: '127.0.0.1', port: 7004 },
    ],
    quorumRequired: 3,
    publicVerificationKeyHex: '9c1b0d3e6f4a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2d',
    privateSigningKeyHex: '0303030303030303030303030303030303030303030303030303030303030303',
  },
  'val-delta-04': {
    nodeId: 'val-delta-04',
    name: 'Validator Delta',
    role: 'Redundant Consensus Node',
    location: 'Recovery Enclave',
    listenHost: '127.0.0.1',
    listenPort: 7004,
    httpPort: 8004,
    dataDir: path.resolve(process.cwd(), '.validator-data/val-delta-04'),
    peers: [
      { nodeId: 'val-alpha-01', host: '127.0.0.1', port: 7001 },
      { nodeId: 'val-bravo-02', host: '127.0.0.1', port: 7002 },
      { nodeId: 'val-gamma-03', host: '127.0.0.1', port: 7003 },
    ],
    quorumRequired: 3,
    publicVerificationKeyHex: 'a1b2c3d4e5f67a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    privateSigningKeyHex: '0404040404040404040404040404040404040404040404040404040404040404',
  },
};

/**
 * Get configuration for a specific node ID or alias (e.g. 'val-a', 'a', 'val-alpha-01').
 * Allows environment overrides for ports and data directory.
 */
export function getValidatorConfig(nodeIdentifier: string): ValidatorNodeConfig {
  const normalizedId = normalizeNodeId(nodeIdentifier);
  const baseConfig = CLUSTER_VALIDATOR_CONFIGS[normalizedId];
  if (!baseConfig) {
    throw new Error(`Unknown validator node identifier: ${nodeIdentifier}. Valid nodes: val-alpha-01, val-bravo-02, val-gamma-03, val-delta-04`);
  }

  // Clone to avoid accidental in-memory pollution across tests
  const config: ValidatorNodeConfig = JSON.parse(JSON.stringify(baseConfig));

  // Environment variable overrides
  if (process.env.VALIDATOR_LISTEN_HOST) {
    config.listenHost = process.env.VALIDATOR_LISTEN_HOST;
  }
  if (process.env.VALIDATOR_LISTEN_PORT) {
    config.listenPort = parseInt(process.env.VALIDATOR_LISTEN_PORT, 10);
  }
  if (process.env.VALIDATOR_HTTP_PORT) {
    config.httpPort = parseInt(process.env.VALIDATOR_HTTP_PORT, 10);
  }
  if (process.env.VALIDATOR_DATA_DIR) {
    config.dataDir = path.resolve(process.cwd(), process.env.VALIDATOR_DATA_DIR);
  }

  return config;
}

export function normalizeNodeId(id: string): string {
  const lower = id.toLowerCase().trim();
  if (lower === 'a' || lower === 'val-a' || lower === 'validator-a') return 'val-alpha-01';
  if (lower === 'b' || lower === 'val-b' || lower === 'validator-b') return 'val-bravo-02';
  if (lower === 'c' || lower === 'val-c' || lower === 'validator-c') return 'val-gamma-03';
  if (lower === 'd' || lower === 'val-d' || lower === 'validator-d') return 'val-delta-04';
  return lower;
}
