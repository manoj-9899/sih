/**
 * Standalone Validator Node Process Entrypoint.
 *
 * Runs an independent Validator Node process with its own:
 * - Isolated persistent local ledger storage (.validator-data/<nodeId>/ledger.json)
 * - P2P TCP socket server for node-to-node replication
 * - HTTP endpoint for local status, health check, and transaction submission
 * - Graceful shutdown on SIGINT/SIGTERM
 *
 * Usage:
 *   npx tsx src/validator/nodeProcess.ts --node=val-alpha-01
 *   npx tsx src/validator/nodeProcess.ts --node=val-bravo-02
 *   npx tsx src/validator/nodeProcess.ts --node=val-gamma-03
 *   npx tsx src/validator/nodeProcess.ts --node=val-delta-04
 */

import http from 'node:http';
import { getValidatorConfig } from './config';
import { ValidatorNodeEngine } from './validatorNode';

// Parse node identifier from command line arguments or environment
function parseNodeId(): string {
  const args = process.argv.slice(2);
  for (const arg of args) {
    if (arg.startsWith('--node=')) {
      return arg.split('=')[1];
    }
    if (arg === '-n' && args[args.indexOf(arg) + 1]) {
      return args[args.indexOf(arg) + 1];
    }
  }
  return process.env.VALIDATOR_NODE_ID || 'val-alpha-01';
}

async function main() {
  const targetId = parseNodeId();
  const config = getValidatorConfig(targetId);
  const node = new ValidatorNodeEngine(config);

  console.log(`[ValidatorProcess] Initializing ${config.name} (${config.nodeId})...`);
  console.log(`[ValidatorProcess] P2P Listen: ${config.listenHost}:${config.listenPort}`);
  console.log(`[ValidatorProcess] HTTP Listen: ${config.listenHost}:${config.httpPort}`);
  console.log(`[ValidatorProcess] Data Directory: ${config.dataDir}`);

  // Start the P2P node engine
  await node.start();
  console.log(`[ValidatorProcess] ${config.name} started successfully. Head height: ${node.getLatestBlock().height}`);

  // Start lightweight HTTP server for local inspection
  const httpServer = http.createServer(async (req, res) => {
    // Set CORS headers for local inspection
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    const url = new URL(req.url || '/', `http://${config.listenHost}:${config.httpPort}`);

    // GET /status
    if (req.method === 'GET' && url.pathname === '/status') {
      const head = node.getLedgerHead();
      const status = {
        nodeId: node.nodeId,
        name: node.name,
        status: node.status,
        listenPort: config.listenPort,
        httpPort: config.httpPort,
        height: head.height,
        headBlockHash: head.headBlockHash,
        totalTransactions: head.totalTransactions,
        connectedPeers: node.getConnectedPeerIds(),
        peersTable: node.getPeerStatusTable(),
        dataDir: config.dataDir,
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(status, null, 2));
      return;
    }

    // GET /chain
    if (req.method === 'GET' && url.pathname === '/chain') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(node.getChain(), null, 2));
      return;
    }

    // GET /mempool
    if (req.method === 'GET' && url.pathname === '/mempool') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(node.getMempool(), null, 2));
      return;
    }

    // POST /submit-tx
    if (req.method === 'POST' && url.pathname === '/submit-tx') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', async () => {
        try {
          const tx = JSON.parse(body);
          const result = await node.submitTransaction(tx);
          res.writeHead(result.success ? 200 : 400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (e: any) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: e.message }));
        }
      });
      return;
    }

    // POST /propose-block
    if (req.method === 'POST' && url.pathname === '/propose-block') {
      const proposal = await node.proposeBlock();
      res.writeHead(proposal ? 200 : 400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: !!proposal, proposal }));
      return;
    }

    // 404 fallback
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
  });

  httpServer.listen(config.httpPort, config.listenHost, () => {
    console.log(`[ValidatorProcess] HTTP API ready at http://${config.listenHost}:${config.httpPort}`);
  });

  // Graceful shutdown
  const shutdown = async () => {
    console.log(`\n[ValidatorProcess] Shutting down ${config.name}...`);
    httpServer.close();
    await node.stop();
    console.log(`[ValidatorProcess] ${config.name} stopped cleanly.`);
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

// Execute if run directly
if (process.argv[1]?.endsWith('nodeProcess.ts') || process.argv[1]?.endsWith('nodeProcess.js')) {
  main().catch((err) => {
    console.error('[ValidatorProcess] Fatal error:', err);
    process.exit(1);
  });
}
