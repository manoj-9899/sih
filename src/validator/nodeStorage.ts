/**
 * Isolated Local Ledger Storage for Validator Nodes.
 *
 * Each validator node persists its own independent copy of the ledger
 * to its own logically isolated data directory on disk.
 *
 * Node A -> .validator-data/val-alpha-01/ledger.json
 * Node B -> .validator-data/val-bravo-02/ledger.json
 * Node C -> .validator-data/val-gamma-03/ledger.json
 * Node D -> .validator-data/val-delta-04/ledger.json
 *
 * Guarantees:
 * - Zero shared mutable ledger objects between nodes
 * - Atomic disk writes (temp file + rename)
 * - Safe fallback to in-memory store if disk write fails
 */

import fs from 'node:fs';
import path from 'node:path';
import { LedgerBlock } from '../types';

export class NodeStorage {
  private dataDir: string;
  private ledgerFilePath: string;
  private memoryBlocks: LedgerBlock[] = [];

  constructor(dataDir: string) {
    this.dataDir = path.resolve(dataDir);
    this.ledgerFilePath = path.join(this.dataDir, 'ledger.json');
  }

  public getDataDir(): string {
    return this.dataDir;
  }

  /**
   * Ensure directory exists
   */
  private ensureDir(): void {
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
  }

  /**
   * Load all blocks from local isolated storage.
   */
  public async loadBlocks(): Promise<LedgerBlock[]> {
    try {
      this.ensureDir();
      if (!fs.existsSync(this.ledgerFilePath)) {
        return [...this.memoryBlocks];
      }
      const raw = fs.readFileSync(this.ledgerFilePath, 'utf8');
      const parsed: LedgerBlock[] = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        this.memoryBlocks = parsed;
        return JSON.parse(JSON.stringify(parsed));
      }
    } catch (err) {
      console.warn(`[NodeStorage] Failed to read ${this.ledgerFilePath}:`, err);
    }
    return [...this.memoryBlocks];
  }

  /**
   * Atomically save the full chain to local isolated storage.
   */
  public async saveBlocks(blocks: LedgerBlock[]): Promise<void> {
    this.memoryBlocks = JSON.parse(JSON.stringify(blocks));
    try {
      this.ensureDir();
      const tmpPath = `${this.ledgerFilePath}.${Date.now()}.${Math.random().toString(36).substring(2, 8)}.tmp`;
      const data = JSON.stringify(blocks, null, 2);
      fs.writeFileSync(tmpPath, data, 'utf8');
      fs.renameSync(tmpPath, this.ledgerFilePath);
    } catch (err) {
      console.warn(`[NodeStorage] Failed to write ${this.ledgerFilePath}:`, err);
    }
  }

  /**
   * Append a single validated block atomically.
   */
  public async appendBlock(block: LedgerBlock): Promise<void> {
    const blocks = await this.loadBlocks();
    // Duplicate check by height and hash
    const exists = blocks.some((b) => b.height === block.height || b.blockHash === block.blockHash);
    if (!exists) {
      blocks.push(block);
      await this.saveBlocks(blocks);
    }
  }

  /**
   * Clear local node storage (used for tests and resetting).
   */
  public async clear(): Promise<void> {
    this.memoryBlocks = [];
    try {
      if (fs.existsSync(this.ledgerFilePath)) {
        fs.unlinkSync(this.ledgerFilePath);
      }
    } catch {
      // Ignore cleanup error
    }
  }
}
