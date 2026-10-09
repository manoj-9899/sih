import './setup.ts';
import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import { sessionManager, AuthenticatedSession } from '../src/crypto/sessionManager.ts';
import { createUnifiedEncryptedKeystore } from '../src/crypto/keystore.ts';
import { generateRecipientPqcKeys, bytesToHex } from '../src/crypto/pqc.ts';
import { Recipient, EncryptedPackage, ClassifiedDocument } from '../src/types';
import { DistributionService } from '../src/services/distributionService.ts';
import { airGappedLedger } from '../src/ledger/dlt.ts';
import { airGappedStorage } from '../src/storage/airGappedStorage.ts';

describe('TEST GROUP 7: Authenticated Session Manager & Decryption Authorization (AUTH-SESSION-01 to AUTH-SESSION-17)', () => {
  const aliceId = 'USR-ALICE-SESS-01';
  const alicePass = 'AliceSessionPassword2026!';
  const bobId = 'USR-BOB-SESS-02';
  const bobPass = 'BobSessionPassword2026!';

  async function createTestRecipient(id: string, name: string, pass: string): Promise<Recipient> {
    const keys = await generateRecipientPqcKeys();
    const keystore = await createUnifiedEncryptedKeystore(
      id,
      keys.fingerprint,
      keys.kemSecretKey,
      keys.dsaSecretKey,
      pass
    );

    const recipient: Recipient = {
      id,
      name,
      role: 'Intelligence Officer',
      organization: 'Defense Command',
      clearanceLevel: 'TOP SECRET // SCI',
      avatarInitials: name.split(' ').map((p) => p[0]).join(''),
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(keys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(keys.dsaPublicKey),
        encryptedKeystore: keystore,
        keyFingerprint: keys.fingerprint,
        registeredAt: Date.now(),
      },
    };

    airGappedLedger.registerRecipient(recipient);
    await airGappedStorage.saveKeystore(keystore);
    return recipient;
  }

  const sampleDoc: ClassifiedDocument = {
    id: 'DOC-CONFIDENTIAL-SESSION-01',
    title: 'Joint Task Force Tactical Plan',
    classification: 'TOP SECRET // SCI',
    caveats: 'NOFORN',
    originatingOffice: 'Joint Staff',
    summary: 'Tactical deployment plan for cyber readiness enclave.',
    rawText: 'HIGHLY CLASSIFIED SESSION DATA: ALL ACCESS LOGGED TO DLT.',
    visualPages: [],
    createdAt: Date.now(),
  };

  it('AUTH-SESSION-01: Correct passphrase creates an authenticated session', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    const session = await sessionManager.createSession(alice, alicePass);

    assert.ok(session, 'Session must be created');
    assert.strictEqual(session.userId, alice.id);
    assert.strictEqual(session.status, 'ACTIVE');
    assert.ok(session.unlockedKeys, 'Unlocked private keys must be present in active session');
    assert.strictEqual(session.unlockedKeys.kemSecretKey.length, 2400);
    assert.strictEqual(session.unlockedKeys.dsaSecretKey.length, 4032);
  });

  it('AUTH-SESSION-02: Incorrect passphrase does not create a session', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    sessionManager.lockSession();

    await assert.rejects(
      async () => {
        await sessionManager.createSession(alice, 'WrongPassphraseTotally!');
      },
      /operation failed|tag mismatch|failed/i
    );

    assert.strictEqual(sessionManager.getActiveSession(), null);
    assert.strictEqual(sessionManager.isSessionActive(), false);
  });

  it('AUTH-SESSION-03: Active session reports authenticated state', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    await sessionManager.createSession(alice, alicePass);

    assert.strictEqual(sessionManager.isSessionActive(), true);
    const active = sessionManager.getActiveSession();
    assert.ok(active);
    assert.strictEqual(active.userId, alice.id);
  });

  it('AUTH-SESSION-04: Session belongs to exactly one user', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    const session = await sessionManager.createSession(alice, alicePass);

    assert.strictEqual(session.userId, alice.id);
    assert.notStrictEqual(session.userId, bobId);
  });

  it('AUTH-SESSION-05: Session expiration disables access', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    sessionManager.setConfig({ inactivityTimeoutMs: 1 }); // 1 millisecond expiration
    await sessionManager.createSession(alice, alicePass);

    // Wait 5ms to guarantee timeout has passed
    await new Promise((r) => setTimeout(r, 10));

    const session = sessionManager.getActiveSession();
    assert.strictEqual(session, null, 'Expired session must return null');
    assert.strictEqual(sessionManager.isSessionActive(), false);

    // Reset default timeout
    sessionManager.setConfig({ inactivityTimeoutMs: 15 * 60 * 1000 });
  });

  it('AUTH-SESSION-06: Explicit lock disables access and clears unlocked keys', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    await sessionManager.createSession(alice, alicePass);
    assert.strictEqual(sessionManager.isSessionActive(), true);

    sessionManager.lockSession();

    assert.strictEqual(sessionManager.getActiveSession(), null);
    assert.strictEqual(sessionManager.isSessionActive(), false);
  });

  it('AUTH-SESSION-07: Private keys are not persisted when a session is created', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    await sessionManager.createSession(alice, alicePass);

    // Verify keystore storage contains encrypted keystore with saltHex
    const ksStored = await airGappedStorage.getKeystore(alice.id);
    assert.ok(ksStored, 'Keystore must be saved');
    assert.strictEqual(ksStored.saltHex, alice.keys.encryptedKeystore!.saltHex);

    // Verify localStorage item has no raw private keys
    const lsRaw = localStorage.getItem('sih_keystores') || '';
    assert.strictEqual(
      lsRaw.includes('kemSecretKeyHex'),
      false,
      'Plaintext kemSecretKeyHex must not exist in storage'
    );
    assert.strictEqual(
      lsRaw.includes('dsaSecretKeyHex'),
      false,
      'Plaintext dsaSecretKeyHex must not exist in storage'
    );
  });

  it('AUTH-SESSION-08: Only the authenticated user\'s private keys are available in active session', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    const session = await sessionManager.createSession(alice, alicePass);

    assert.strictEqual(session.userId, alice.id);
    assert.strictEqual(session.keyFingerprint, alice.keys.keyFingerprint);
  });

  it('AUTH-SESSION-09: Alice cannot decrypt Bob\'s package', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    const bob = await createTestRecipient(bobId, 'Col. Bob Martinez', bobPass);

    // Create package encrypted ONLY for Bob
    const bobOnlyPackage = await DistributionService.createEncryptedPackage(sampleDoc, [bob]);

    // Alice authenticates
    const aliceSession = await sessionManager.createSession(alice, alicePass);

    // Alice attempts to decrypt Bob's package
    await assert.rejects(
      async () => {
        await DistributionService.executeRecipientDecryption(bobOnlyPackage, alice, aliceSession);
      },
      /Access Denied: Recipient Dr. Alice Vance is not authorized/i,
      'Alice must be rejected because package has no envelope for Alice'
    );
  });

  it('AUTH-SESSION-10: Alice cannot sign an event as Bob (Impersonation Rejection)', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    const bob = await createTestRecipient(bobId, 'Col. Bob Martinez', bobPass);

    const bobPackage = await DistributionService.createEncryptedPackage(sampleDoc, [bob]);

    // Alice authenticates
    const aliceSession = await sessionManager.createSession(alice, alicePass);

    // Alice attempts to pass Bob's recipient object to decryption while logged in as Alice
    await assert.rejects(
      async () => {
        await DistributionService.executeRecipientDecryption(bobPackage, bob, aliceSession);
      },
      /ImpersonationAttemptBlocked/i,
      'System must block impersonating Bob under Alice\'s session'
    );
  });

  it('AUTH-SESSION-11: Changing frontend user state does not bypass authenticated session', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    const bob = await createTestRecipient(bobId, 'Col. Bob Martinez', bobPass);

    await sessionManager.createSession(alice, alicePass);

    // Frontend attempts to trick service by passing Bob's object while activeSession is Alice
    const sharedPackage = await DistributionService.createEncryptedPackage(sampleDoc, [alice, bob]);

    await assert.rejects(
      async () => {
        await DistributionService.executeRecipientDecryption(sharedPackage, bob);
      },
      /ImpersonationAttemptBlocked/i
    );
  });

  it('AUTH-SESSION-12: Direct decrypt call without an active session is rejected', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    const pkg = await DistributionService.createEncryptedPackage(sampleDoc, [alice]);

    sessionManager.lockSession(); // Ensure no active session

    await assert.rejects(
      async () => {
        await DistributionService.executeRecipientDecryption(pkg, alice, null);
      },
      /AuthenticationRequired/i
    );
  });

  it('AUTH-SESSION-13: Direct signature call without an active session is rejected', async () => {
    sessionManager.lockSession();

    assert.throws(
      () => {
        sessionManager.requireAuthenticatedSession();
      },
      /AuthenticationRequired/i
    );
  });

  it('AUTH-SESSION-14: Expired session cannot decrypt', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    const pkg = await DistributionService.createEncryptedPackage(sampleDoc, [alice]);

    sessionManager.setConfig({ inactivityTimeoutMs: 1 });
    const session = await sessionManager.createSession(alice, alicePass);

    await new Promise((r) => setTimeout(r, 10)); // expire

    await assert.rejects(
      async () => {
        await DistributionService.executeRecipientDecryption(pkg, alice, session);
      },
      /AuthenticationRequired/i
    );

    sessionManager.setConfig({ inactivityTimeoutMs: 15 * 60 * 1000 });
  });

  it('AUTH-SESSION-15: Locked session cannot sign or decrypt', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    const pkg = await DistributionService.createEncryptedPackage(sampleDoc, [alice]);

    await sessionManager.createSession(alice, alicePass);
    sessionManager.lockSession();

    await assert.rejects(
      async () => {
        await DistributionService.executeRecipientDecryption(pkg, alice);
      },
      /AuthenticationRequired/i
    );
  });

  it('AUTH-SESSION-16: Session timeout works correctly via touchSession', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    sessionManager.setConfig({ inactivityTimeoutMs: 50 });
    const session = await sessionManager.createSession(alice, alicePass);

    // Sleep 25ms, then touch session to extend
    await new Promise((r) => setTimeout(r, 25));
    sessionManager.touchSession();

    // After another 35ms, original 50ms would have expired, but touched session is still active
    await new Promise((r) => setTimeout(r, 35));
    assert.strictEqual(sessionManager.isSessionActive(), true);

    // Sleep 60ms without touch: now expired
    await new Promise((r) => setTimeout(r, 60));
    assert.strictEqual(sessionManager.isSessionActive(), false);

    sessionManager.setConfig({ inactivityTimeoutMs: 15 * 60 * 1000 });
  });

  it('AUTH-SESSION-17: Unlocking Alice after Bob does not retain Bob\'s private keys in active session', async () => {
    const alice = await createTestRecipient(aliceId, 'Dr. Alice Vance', alicePass);
    const bob = await createTestRecipient(bobId, 'Col. Bob Martinez', bobPass);

    // Unlock Bob
    const bobSession = await sessionManager.createSession(bob, bobPass);
    assert.strictEqual(bobSession.userId, bob.id);

    // Unlock Alice
    const aliceSession = await sessionManager.createSession(alice, alicePass);
    assert.strictEqual(aliceSession.userId, alice.id);

    const active = sessionManager.getActiveSession();
    assert.strictEqual(active?.userId, alice.id);
    assert.strictEqual(active?.keyFingerprint, alice.keys.keyFingerprint);
    assert.notStrictEqual(active?.keyFingerprint, bob.keys.keyFingerprint);
  });
});
