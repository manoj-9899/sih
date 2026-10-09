/**
 * Local Validator Cluster Daemon.
 *
 * Runs and manages the 4 offline validator nodes in independent logical runtimes:
 * - Validator Alpha (val-alpha-01): Port 7001 / HTTP 8001
 * - Validator Bravo (val-bravo-02): Port 7002 / HTTP 8002
 * - Validator Gamma (val-gamma-03): Port 7003 / HTTP 8003
 * - Validator Delta (val-delta-04): Port 7004 / HTTP 8004
 *
 * Provides cluster orchestration:
 * - Start/stop entire cluster
 * - Stop/restart individual nodes (for node failure & recovery testing)
 * - Query cluster-wide status and replication health
 */

import { CLUSTER_VALIDATOR_CONFIGS } from './config';
import { ValidatorNodeEngine } from './validatorNode';

export class LocalValidatorDaemon {
  private nodes: Map<string, ValidatorNodeEngine> = new Map();

  constructor() {
    for (const [id, config] of Object.entries(CLUSTER_VALIDATOR_CONFIGS)) {
      this.nodes.set(id, new ValidatorNodeEngine(config));
    }
  }

  /**
   * Start all validator nodes and form the offline peer network.
   */
  public async startCluster(): Promise<void> {
    console.log('[ValidatorDaemon] Starting 4-node air-gapped cluster...');

    // 1. Start all node servers
    for (const node of this.nodes.values()) {
      await node.start();
    }

    // 2. Allow peer connections to interlink
    await new Promise((r) => setTimeout(r, 100));
    for (const node of this.nodes.values()) {
      await node.connectConfiguredPeers();
    }

    console.log('[ValidatorDaemon] Cluster active. 4/4 nodes running in isolated enclaves.');
  }

  /**
   * Stop all validator nodes cleanly.
   */
  public async stopCluster(): Promise<void> {
    console.log('[ValidatorDaemon] Stopping all nodes...');
    for (const node of this.nodes.values()) {
      await node.stop();
    }
    console.log('[ValidatorDaemon] All validator nodes stopped.');
  }

  /**
   * Get an individual node by ID.
   */
  public getNode(nodeId: string): ValidatorNodeEngine | undefined {
    return this.nodes.get(nodeId);
  }

  public getAllNodes(): ValidatorNodeEngine[] {
    return Array.from(this.nodes.values());
  }

  /**
   * Stop a single node to simulate a node offline/failure scenario.
   */
  public async stopNode(nodeId: string): Promise<boolean> {
    const node = this.nodes.get(nodeId);
    if (!node) return false;
    await node.stop();
    console.log(`[ValidatorDaemon] Node ${nodeId} taken OFFLINE.`);
    return true;
  }

  /**
   * Restart a stopped node to simulate recovery and catch-up synchronization.
   */
  public async restartNode(nodeId: string): Promise<boolean> {
    const node = this.nodes.get(nodeId);
    if (!node) return false;
    await node.start();
    await node.connectConfiguredPeers();
    console.log(`[ValidatorDaemon] Node ${nodeId} RESTARTED and reconnected.`);
    return true;
  }

  /**
   * Inspect cluster-wide replication status.
   */
  public getClusterStatus() {
    const statuses = [];
    for (const node of this.nodes.values()) {
      const head = node.getLedgerHead();
      statuses.push({
        nodeId: node.nodeId,
        name: node.name,
        status: node.status,
        listenPort: node.config.listenPort,
        height: head.height,
        headBlockHash: head.headBlockHash,
        totalTransactions: head.totalTransactions,
        connectedPeers: node.getConnectedPeerIds(),
        dataDir: node.config.dataDir,
      });
    }
    return statuses;
  }
}

// Global daemon singleton for in-app / test orchestration
export const localValidatorDaemon = new LocalValidatorDaemon();

async function main() {
  const daemon = new LocalValidatorDaemon();
  await daemon.startCluster();

  const shutdown = async () => {
    console.log('\n[ValidatorDaemon] Stopping daemon...');
    await daemon.stopCluster();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

if (process.argv[1]?.endsWith('daemon.ts') || process.argv[1]?.endsWith('daemon.js')) {
  main().catch((err) => {
    console.error('[ValidatorDaemon] Fatal error:', err);
    process.exit(1);
  });
}
