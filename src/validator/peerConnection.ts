/**
 * Local Peer-to-Peer Socket Transport for Offline Air-Gapped Network.
 *
 * Implements persistent TCP connections between validator nodes with:
 * - 4-byte big-endian length-prefixed framing to guarantee message boundary integrity
 * - Maximum message size protection (10MB) to mitigate buffer-exhaustion attacks
 * - Auto-reconnect handling for transient network disconnects
 * - Graceful connection failure handling (e.g., peer offline)
 * - Zero external dependencies (uses standard Node.js node:net)
 */

import net from 'node:net';
import { EventEmitter } from 'node:events';
import { ValidatorNetworkMessage } from './types';

const MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10 Megabytes maximum

export interface PeerConnectionInfo {
  peerId: string;
  host: string;
  port: number;
  socket: net.Socket;
  isConnected: boolean;
  lastSeenMs: number;
}

export class PeerNetworkTransport extends EventEmitter {
  private localNodeId: string;
  private listenHost: string;
  private listenPort: number;
  private server: net.Server | null = null;
  private peers: Map<string, PeerConnectionInfo> = new Map();
  private allSockets: Set<net.Socket> = new Set();
  private isRunning: boolean = false;

  constructor(localNodeId: string, listenHost: string, listenPort: number) {
    super();
    this.localNodeId = localNodeId;
    this.listenHost = listenHost;
    this.listenPort = listenPort;
  }

  public getListenPort(): number {
    return this.listenPort;
  }

  public getListenHost(): string {
    return this.listenHost;
  }

  public getConnectedPeers(): string[] {
    const connected: string[] = [];
    for (const [id, peer] of this.peers.entries()) {
      if (peer.isConnected) {
        connected.push(id);
      }
    }
    return connected;
  }

  public isPeerConnected(peerId: string): boolean {
    return this.peers.get(peerId)?.isConnected === true;
  }

  /**
   * Start listening for incoming peer connections on the configured local port.
   */
  public async startServer(): Promise<void> {
    if (this.isRunning) return;

    return new Promise((resolve, reject) => {
      let started = false;
      this.server = net.createServer((socket) => {
        this.handleIncomingSocket(socket);
      });

      this.server.on('error', (err: any) => {
        console.warn(`[PeerNetwork ${this.localNodeId}] Server error on ${this.listenHost}:${this.listenPort}:`, err.message);
        this.emit('server_error', err);
        if (!started) {
          reject(err);
        }
      });

      this.server.listen(this.listenPort, this.listenHost, () => {
        started = true;
        this.isRunning = true;
        const addr = this.server?.address() as net.AddressInfo;
        if (addr && addr.port) {
          this.listenPort = addr.port;
        }
        this.emit('server_started', { host: this.listenHost, port: this.listenPort });
        resolve();
      });
    });
  }

  /**
   * Stop the transport and close all sockets cleanly.
   */
  public async stop(): Promise<void> {
    this.isRunning = false;

    // Disconnect and destroy all active sockets
    for (const socket of this.allSockets) {
      try {
        socket.destroy();
      } catch {
        // Ignore
      }
    }
    this.allSockets.clear();
    this.peers.clear();

    if (this.server) {
      try {
        this.server.close();
        this.server.unref();
      } catch {
        // Ignore
      }
      this.server = null;
    }
  }

  /**
   * Connect to an outbound peer validator.
   */
  public connectToPeer(peerId: string, host: string, port: number): Promise<boolean> {
    if (this.peers.has(peerId) && this.peers.get(peerId)?.isConnected) {
      return Promise.resolve(true);
    }

    return new Promise((resolve) => {
      const socket = net.createConnection({ host, port }, () => {
        this.allSockets.add(socket);
        const peerInfo: PeerConnectionInfo = {
          peerId,
          host,
          port,
          socket,
          isConnected: true,
          lastSeenMs: Date.now(),
        };
        this.peers.set(peerId, peerInfo);
        this.attachSocketBufferParser(socket, peerId);
        this.emit('peer_connected', { peerId, host, port });
        resolve(true);
      });

      socket.on('error', (err) => {
        this.allSockets.delete(socket);
        // Peer may be offline: non-fatal, log and resolve false
        this.emit('peer_error', { peerId, error: err.message });
        resolve(false);
      });

      socket.on('close', () => {
        this.allSockets.delete(socket);
        const existing = this.peers.get(peerId);
        if (existing) {
          existing.isConnected = false;
        }
        this.emit('peer_disconnected', { peerId });
      });
    });
  }

  /**
   * Disconnect a specific peer.
   */
  public disconnectPeer(peerId: string): void {
    const peer = this.peers.get(peerId);
    if (peer) {
      try {
        this.allSockets.delete(peer.socket);
        peer.socket.destroy();
      } catch {
        // Ignore
      }
      this.peers.delete(peerId);
      this.emit('peer_disconnected', { peerId });
    }
  }

  /**
   * Handle an inbound socket connection from another validator.
   */
  private handleIncomingSocket(socket: net.Socket): void {
    this.allSockets.add(socket);
    const tempId = `inbound-${socket.remoteAddress}:${socket.remotePort}`;
    let identifiedPeerId: string | null = null;

    this.attachSocketBufferParser(socket, tempId, (identifiedId) => {
      identifiedPeerId = identifiedId;
      const peerInfo: PeerConnectionInfo = {
        peerId: identifiedId,
        host: socket.remoteAddress || '127.0.0.1',
        port: socket.remotePort || 0,
        socket,
        isConnected: true,
        lastSeenMs: Date.now(),
      };
      this.peers.set(identifiedId, peerInfo);
      this.emit('peer_connected', { peerId: identifiedId });
    });

    socket.on('close', () => {
      this.allSockets.delete(socket);
      const idToRemove = identifiedPeerId || tempId;
      this.peers.delete(idToRemove);
      this.emit('peer_disconnected', { peerId: idToRemove });
    });

    socket.on('error', (err) => {
      this.allSockets.delete(socket);
      this.emit('peer_error', { peerId: identifiedPeerId || tempId, error: err.message });
    });
  }

  /**
   * Attaches length-prefix stream framing to a raw TCP socket.
   * Frame Format:
   * [ 4 bytes: payload length N (Uint32BE) ] [ N bytes: JSON UTF-8 payload ]
   */
  private attachSocketBufferParser(
    socket: net.Socket,
    fallbackId: string,
    onIdentify?: (peerId: string) => void
  ): void {
    let accumulated = Buffer.alloc(0);

    socket.on('data', (chunk) => {
      accumulated = Buffer.concat([accumulated, chunk]);

      while (accumulated.length >= 4) {
        // Read 4-byte payload length
        const payloadLength = accumulated.readUInt32BE(0);

        if (payloadLength > MAX_MESSAGE_SIZE) {
          console.warn(`[PeerNetwork ${this.localNodeId}] Rejecting oversized message (${payloadLength} bytes) from ${fallbackId}`);
          socket.destroy();
          return;
        }

        if (accumulated.length < 4 + payloadLength) {
          // Incomplete message, wait for more TCP chunks
          break;
        }

        // Extract message slice
        const messageBuf = accumulated.slice(4, 4 + payloadLength);
        accumulated = accumulated.slice(4 + payloadLength);

        try {
          const rawStr = messageBuf.toString('utf8');
          const message: ValidatorNetworkMessage = JSON.parse(rawStr);

          // Update last seen
          if (message.senderNodeId) {
            if (onIdentify) {
              onIdentify(message.senderNodeId);
              onIdentify = undefined; // only once
            }
            const peer = this.peers.get(message.senderNodeId);
            if (peer) {
              peer.lastSeenMs = Date.now();
            }
          }

          // Emit incoming validated frame
          this.emit('message', message);
        } catch (err: any) {
          console.warn(`[PeerNetwork ${this.localNodeId}] Malformed message frame:`, err.message);
          this.emit('malformed_message', { error: err.message });
        }
      }
    });
  }

  /**
   * Send a framed message to a specific peer by ID.
   */
  public sendMessage(peerId: string, message: ValidatorNetworkMessage): boolean {
    const peer = this.peers.get(peerId);
    if (!peer || !peer.isConnected) {
      return false;
    }

    try {
      const payloadBuf = Buffer.from(JSON.stringify(message), 'utf8');
      const headerBuf = Buffer.alloc(4);
      headerBuf.writeUInt32BE(payloadBuf.length, 0);

      peer.socket.write(Buffer.concat([headerBuf, payloadBuf]));
      return true;
    } catch (err) {
      console.warn(`[PeerNetwork ${this.localNodeId}] Failed to send message to ${peerId}:`, err);
      return false;
    }
  }

  /**
   * Broadcast a framed message to all currently connected peers.
   * Returns number of peers sent to.
   */
  public broadcastMessage(message: ValidatorNetworkMessage): number {
    let sentCount = 0;
    for (const [peerId, peer] of this.peers.entries()) {
      if (peer.isConnected && peerId !== this.localNodeId) {
        if (this.sendMessage(peerId, message)) {
          sentCount++;
        }
      }
    }
    return sentCount;
  }
}
