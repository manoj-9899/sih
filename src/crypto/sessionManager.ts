/**
 * Authenticated Local Session Manager.
 * 
 * Manages the ephemeral, in-memory lifecycle of unlocked post-quantum private keys.
 * 
 * Cryptographic Invariant:
 * - Unlocked private keys (ML-KEM-768: 2400 bytes, ML-DSA-65: 4032 bytes) are held ONLY in memory
 *   within this session manager while the session is ACTIVE.
 * - Private keys are NEVER written to IndexedDB, localStorage, sessionStorage, or logs.
 * - Sessions automatically expire after an inactivity timeout (default: 15 minutes).
 * - Explicit lockSession() scrubs key references from the active session.
 * - Note on JavaScript memory: While references are cleared and overwritten with zeros,
 *   browser garbage collection cannot guarantee low-level physical RAM eradication.
 */

import { UnlockedPrivateKeys, unlockKeystoreRecord, EncryptedKeystoreRecord } from './keystore';
import { zeroizeBytes } from './pqc';
import { Recipient } from '../types';
import { airGappedStorage } from '../storage/airGappedStorage';

export interface AuthenticatedSession {
  sessionId: string;
  userId: string;
  userName: string;
  userRole: string;
  userClearance: string;
  avatarInitials: string;
  keyFingerprint: string;
  createdAt: number;
  lastActivityAt: number;
  expiresAt: number;
  status: 'ACTIVE' | 'EXPIRED' | 'LOCKED';
  // Ephemeral, volatile unlocked keys (in memory only, never serialized or saved to disk)
  unlockedKeys?: UnlockedPrivateKeys;
}

export interface SessionConfig {
  inactivityTimeoutMs: number; // default: 15 minutes = 900,000 ms
}

export const DEFAULT_SESSION_CONFIG: SessionConfig = {
  inactivityTimeoutMs: 15 * 60 * 1000,
};

class SessionManager {
  private activeSession: AuthenticatedSession | null = null;
  private config: SessionConfig = { ...DEFAULT_SESSION_CONFIG };
  private listeners: Array<(session: AuthenticatedSession | null) => void> = [];

  /**
   * Configure session timeouts.
   */
  public setConfig(customConfig: Partial<SessionConfig>): void {
    this.config = { ...this.config, ...customConfig };
  }

  public getConfig(): SessionConfig {
    return { ...this.config };
  }

  /**
   * Subscribe to session state changes (unlock, lock, expire).
   */
  public subscribe(callback: (session: AuthenticatedSession | null) => void): () => void {
    this.listeners.push(callback);
    callback(this.getActiveSession());
    return () => {
      this.listeners = this.listeners.filter((l) => l !== callback);
    };
  }

  private notify(): void {
    const current = this.getActiveSession();
    for (const listener of this.listeners) {
      try {
        listener(current);
      } catch (err) {
        console.error('[SessionManager] Listener error:', err);
      }
    }
  }

  /**
   * Attempts to authenticate a recipient by unlocking their local encrypted keystore.
   * Throws an error if the passphrase is invalid, keystore is missing, or keys cannot be unlocked.
   */
  public async createSession(
    recipient: Recipient,
    passphrase: string,
    keystoreRecord?: EncryptedKeystoreRecord
  ): Promise<AuthenticatedSession> {
    if (!passphrase) {
      throw new Error('Passphrase is required to unlock recipient keystore.');
    }

    // 1. Locate encrypted keystore
    let keystore = keystoreRecord || recipient.keys.encryptedKeystore;
    if (!keystore) {
      const loaded = await airGappedStorage.getKeystore(recipient.id);
      if (loaded) {
        keystore = loaded;
      }
    }

    if (!keystore) {
      throw new Error(`KeystoreNotFound: No encrypted keystore found for ${recipient.name} (${recipient.id}).`);
    }

    // 2. Unlock keystore with passphrase (PBKDF2 + AES-256-GCM)
    // Throws OperationError / Tag mismatch if passphrase is incorrect
    const unlocked = await unlockKeystoreRecord(keystore, passphrase);

    return this.startSession(recipient, unlocked);
  }

  /**
   * Directly starts an authenticated session with pre-unlocked keys.
   */
  public startSession(
    recipient: Recipient,
    unlockedKeys: UnlockedPrivateKeys
  ): AuthenticatedSession {
    // Clear previous session if any
    this.lockSession();

    // Construct authenticated session
    const now = Date.now();
    const session: AuthenticatedSession = {
      sessionId: crypto.randomUUID(),
      userId: recipient.id,
      userName: recipient.name,
      userRole: recipient.role,
      userClearance: recipient.clearanceLevel,
      avatarInitials: recipient.avatarInitials,
      keyFingerprint: recipient.keys.keyFingerprint,
      createdAt: now,
      lastActivityAt: now,
      expiresAt: now + this.config.inactivityTimeoutMs,
      status: 'ACTIVE',
      unlockedKeys,
    };

    this.activeSession = session;
    this.notify();
    return session;
  }

  /**
   * Returns the current active session if valid and unexpired.
   * Automatically expires the session if inactivityTimeout has lapsed.
   */
  public getActiveSession(): AuthenticatedSession | null {
    if (!this.activeSession) {
      return null;
    }

    if (this.activeSession.status !== 'ACTIVE') {
      return null;
    }

    const now = Date.now();
    if (now > this.activeSession.expiresAt) {
      this.expireSession();
      return null;
    }

    return this.activeSession;
  }

  /**
   * Checks whether there is an authenticated, unexpired session.
   */
  public isSessionActive(): boolean {
    return this.getActiveSession() !== null;
  }

  /**
   * Updates lastActivityAt and extends the session expiration.
   */
  public touchSession(): void {
    if (this.activeSession && this.activeSession.status === 'ACTIVE') {
      const now = Date.now();
      if (now > this.activeSession.expiresAt) {
        this.expireSession();
      } else {
        this.activeSession.lastActivityAt = now;
        this.activeSession.expiresAt = now + this.config.inactivityTimeoutMs;
      }
    }
  }

  /**
   * Enforces that an active session exists.
   * Throws an error if locked or expired.
   */
  public requireAuthenticatedSession(): AuthenticatedSession {
    const session = this.getActiveSession();
    if (!session || !session.unlockedKeys) {
      throw new Error('AuthenticationRequired: An active authenticated session is required to perform this operation.');
    }
    return session;
  }

  /**
   * Explicitly locks the current session and cleans up volatile key references.
   */
  public lockSession(): void {
    if (this.activeSession) {
      if (this.activeSession.unlockedKeys) {
        // Overwrite secret key buffers with zeros as best-effort in JS runtime
        try {
          zeroizeBytes(this.activeSession.unlockedKeys.kemSecretKey);
          zeroizeBytes(this.activeSession.unlockedKeys.dsaSecretKey);
          this.activeSession.unlockedKeys.kemSecretKeyHex = '';
          this.activeSession.unlockedKeys.dsaSecretKeyHex = '';
        } catch (_err) {
          // ignore buffer fill errors
        }
        delete this.activeSession.unlockedKeys;
      }
      this.activeSession.status = 'LOCKED';
      this.activeSession = null;
      this.notify();
    }
  }

  /**
   * Marks session as expired and scrubs sensitive keys.
   */
  public expireSession(): void {
    if (this.activeSession) {
      if (this.activeSession.unlockedKeys) {
        try {
          zeroizeBytes(this.activeSession.unlockedKeys.kemSecretKey);
          zeroizeBytes(this.activeSession.unlockedKeys.dsaSecretKey);
          this.activeSession.unlockedKeys.kemSecretKeyHex = '';
          this.activeSession.unlockedKeys.dsaSecretKeyHex = '';
        } catch (_err) {
          // ignore
        }
        delete this.activeSession.unlockedKeys;
      }
      this.activeSession.status = 'EXPIRED';
      this.activeSession = null;
      this.notify();
    }
  }
}

export const sessionManager = new SessionManager();
