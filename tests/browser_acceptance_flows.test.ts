import './setup';
import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { AssignmentService } from '../src/services/assignmentService';
import { DistributionService } from '../src/services/distributionService';
import { ReceiptService } from '../src/services/receiptService';
import { airGappedStorage } from '../src/storage/airGappedStorage';
import { airGappedLedger } from '../src/ledger/dlt';
import { sessionManager } from '../src/crypto/sessionManager';
import { generateRecipientPqcKeys, bytesToHex } from '../src/crypto/pqc';
import { createUnifiedEncryptedKeystore, unlockKeystoreRecord } from '../src/crypto/keystore';
import { Recipient, ClassifiedDocument } from '../src/types';

describe('AEGIS-PQC: BROWSER ACCEPTANCE & INTEGRATION FLOWS (UI-FLOW-01 to UI-FLOW-07)', () => {
  let doc1: ClassifiedDocument;
  let doc2: ClassifiedDocument;
  let alice: Recipient;
  let bob: Recipient;
  let aliceKeystore: any;
  let bobKeystore: any;
  const alicePassphrase = 'AlicePassword2026!';
  const bobPassphrase = 'BobPassword2026!';

  beforeEach(async () => {
    sessionManager.lockSession();
    await airGappedStorage.clearAll();
    await airGappedLedger.initGenesis();

    const aliceKeys = await generateRecipientPqcKeys();
    const bobKeys = await generateRecipientPqcKeys();

    aliceKeystore = await createUnifiedEncryptedKeystore(
      'REC-ALICE-01',
      aliceKeys.fingerprint,
      aliceKeys.kemSecretKey,
      aliceKeys.dsaSecretKey,
      alicePassphrase
    );

    bobKeystore = await createUnifiedEncryptedKeystore(
      'REC-BOB-01',
      bobKeys.fingerprint,
      bobKeys.kemSecretKey,
      bobKeys.dsaSecretKey,
      bobPassphrase
    );

    await airGappedStorage.saveKeystore(aliceKeystore);
    await airGappedStorage.saveKeystore(bobKeystore);

    alice = {
      id: 'REC-ALICE-01',
      name: 'Dr. Alice Vance',
      organization: 'Defense Cyber Directorate',
      role: 'Principal Research Scientist',
      clearanceLevel: 'TOP SECRET // SCI',
      avatarInitials: 'AV',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(aliceKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(aliceKeys.dsaPublicKey),
        encryptedKeystore: aliceKeystore,
        keyFingerprint: aliceKeys.fingerprint,
      },
      createdAt: Date.now(),
    };

    bob = {
      id: 'REC-BOB-01',
      name: 'Col. Robert Vance',
      organization: 'Air Defense Command',
      role: 'Operations Commander',
      clearanceLevel: 'SECRET',
      avatarInitials: 'RV',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(bobKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(bobKeys.dsaPublicKey),
        encryptedKeystore: bobKeystore,
        keyFingerprint: bobKeys.fingerprint,
      },
      createdAt: Date.now(),
    };

    airGappedLedger.registerRecipient(alice);
    airGappedLedger.registerRecipient(bob);
    await airGappedStorage.saveRecipient(alice);
    await airGappedStorage.saveRecipient(bob);

    doc1 = {
      id: 'DOC-ALPHA-001',
      title: 'Satellite Orbital Trajectory Alpha',
      classification: 'TOP SECRET // SCI',
      caveats: 'NOFORN',
      originatingOffice: 'Aerospace Defense',
      summary: 'Orbital vectors',
      rawText: 'ORBITAL DATA: Trajectory vectors for defense constellation 7.',
      visualPages: [],
      createdAt: Date.now(),
      fileSizeBytes: 64,
    };

    doc2 = {
      id: 'DOC-BRAVO-002',
      title: 'Tactical Frequency Allocation Bravo',
      classification: 'SECRET',
      caveats: 'ORCON',
      originatingOffice: 'Signals Command',
      summary: 'Frequencies',
      rawText: 'SIGNALS DATA: Electronic warfare spectrum allocation grid.',
      visualPages: [],
      createdAt: Date.now(),
      fileSizeBytes: 64,
    };
  });

  async function loginAlice() {
    const unlocked = await unlockKeystoreRecord(aliceKeystore, alicePassphrase);
    return sessionManager.startSession(alice, unlocked);
  }

  async function loginBob() {
    const unlocked = await unlockKeystoreRecord(bobKeystore, bobPassphrase);
    return sessionManager.startSession(bob, unlocked);
  }

  test('UI-FLOW-01: Two separate recipient identities have strict inbox isolation', async () => {
    // Distribute doc1 strictly to Alice
    await DistributionService.createEncryptedPackage(doc1, [alice]);
    // Distribute doc2 strictly to Bob
    await DistributionService.createEncryptedPackage(doc2, [bob]);

    // 1. Log in as Alice
    const aliceSession = await loginAlice();
    const aliceNotifs = await AssignmentService.getNotificationsForRecipient(alice.id, aliceSession);

    assert.equal(aliceNotifs.length, 1);
    assert.equal(aliceNotifs[0].recipientId, alice.id);
    assert.equal(aliceNotifs[0].documentTitle, doc1.title);

    // Verify Alice cannot query Bob's inbox while Alice session is active
    await assert.rejects(
      async () => {
        await AssignmentService.getNotificationsForRecipient(bob.id, aliceSession);
      },
      (err: Error) => err.message.includes('UnauthorizedSession')
    );

    // 2. Switch to Bob
    const bobSession = await loginBob();
    const bobNotifs = await AssignmentService.getNotificationsForRecipient(bob.id, bobSession);

    assert.equal(bobNotifs.length, 1);
    assert.equal(bobNotifs[0].recipientId, bob.id);
    assert.equal(bobNotifs[0].documentTitle, doc2.title);

    // Verify Bob cannot query Alice's inbox
    await assert.rejects(
      async () => {
        await AssignmentService.getNotificationsForRecipient(alice.id, bobSession);
      },
      (err: Error) => err.message.includes('UnauthorizedSession')
    );
  });

  test('UI-FLOW-02: Account switching and session locking scrubs active session state', async () => {
    await DistributionService.createEncryptedPackage(doc1, [alice]);
    const aliceSession = await loginAlice();

    assert.equal(sessionManager.getActiveSession()?.userId, alice.id);
    assert.ok(sessionManager.getActiveSession()?.unlockedKeys?.dsaSecretKey);

    // Explicit session lock
    sessionManager.lockSession();
    assert.equal(sessionManager.getActiveSession(), null);

    // Switch to Bob
    const bobSession = await loginBob();
    assert.equal(sessionManager.getActiveSession()?.userId, bob.id);
    assert.notEqual(sessionManager.getActiveSession()?.keyFingerprint, alice.keys.keyFingerprint);
  });

  test('UI-FLOW-03: Read-state persistence across sessions and simulated reload', async () => {
    // Send two distributions to Alice
    await DistributionService.createEncryptedPackage(doc1, [alice]);
    await DistributionService.createEncryptedPackage(doc2, [alice]);

    // 1. Initial unread check
    const session1 = await loginAlice();
    let notifs = await AssignmentService.getNotificationsForRecipient(alice.id, session1);
    assert.equal(notifs.length, 2);
    assert.equal(notifs.filter((n) => !n.read).length, 2);

    // 2. Mark first notification as read
    const firstNotif = notifs[0];
    await AssignmentService.markNotificationRead(firstNotif.notificationId, alice.id, session1);

    // 3. Simulate page reload / session lock & unlock
    sessionManager.lockSession();
    const session2 = await loginAlice();

    // 4. Verify read state persisted
    notifs = await AssignmentService.getNotificationsForRecipient(alice.id, session2);
    const updatedFirst = notifs.find((n) => n.notificationId === firstNotif.notificationId);
    assert.equal(updatedFirst?.read, true);
    assert.ok(typeof updatedFirst?.readAt === 'number');

    const secondNotif = notifs.find((n) => n.notificationId !== firstNotif.notificationId);
    assert.equal(secondNotif?.read, false);

    // 5. Mark all as read
    await AssignmentService.markAllNotificationsRead(alice.id, session2);
    notifs = await AssignmentService.getNotificationsForRecipient(alice.id, session2);
    assert.equal(notifs.every((n) => n.read), true);
  });

  test('UI-FLOW-04: Package navigation from notification loads package into Decrypt workflow', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc1, [alice]);
    const aliceSession = await loginAlice();

    const notifs = await AssignmentService.getNotificationsForRecipient(alice.id, aliceSession);
    const notif = notifs[0];
    assert.ok(notif.packageId);

    // Recipient clicks "Open in Decrypt View" in the inbox drawer
    const loadedPkg = await airGappedStorage.getPackage(notif.packageId);
    assert.ok(loadedPkg);
    assert.equal(loadedPkg.packageId, pkg.packageId);
    assert.equal(loadedPkg.documentTitle, doc1.title);

    // Decrypt execution proceeds seamlessly
    const decResult = await DistributionService.executeRecipientDecryption(loadedPkg, alice, aliceSession);
    assert.ok(decResult.watermarkedText);
    assert.ok(decResult.decryptionEvent);
    assert.ok(decResult.blockHeight > 0);
  });

  test('UI-FLOW-05: Revoked assignment behavior updates inbox notification and prevents unauthorized access', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc1, [alice]);
    const aliceSession = await loginAlice();

    const assignments = await AssignmentService.getAssignmentsForRecipient(alice.id, aliceSession);
    assert.equal(assignments.length, 1);
    const asgn = assignments[0];

    // Revoke assignment
    await AssignmentService.revokeAssignment(asgn.assignmentId, 'Security clearance suspended pending investigation');

    // Verify notification was delivered to Alice
    const notifs = await AssignmentService.getNotificationsForRecipient(alice.id, aliceSession);
    const revNotif = notifs.find((n) => n.type === 'ACCESS_REVOKED');
    assert.ok(revNotif);
    assert.ok(revNotif.message.includes('revoked'));

    // Check assignment status is REVOKED
    const updatedAssignments = await AssignmentService.getAssignmentsForRecipient(alice.id, aliceSession);
    assert.equal(updatedAssignments[0].status, 'REVOKED');
    assert.equal(updatedAssignments[0].revocationReason, 'Security clearance suspended pending investigation');
  });

  test('UI-FLOW-06: End-to-end receipt download, upload, and verification workflow', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc1, [alice]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    // Simulate file download (.sihrcpt) and file upload back into verification modal
    const serializedReceiptFile = ReceiptService.serializeReceipt(receipt);
    const fileBytes = new TextEncoder().encode(serializedReceiptFile);

    // Verify uploaded file bytes
    const verification = await ReceiptService.verifyReceipt(fileBytes);
    assert.equal(verification.valid, true);
    assert.equal(verification.signatureValid, true);
    assert.equal(verification.identityBound, true);
    assert.equal(verification.ledgerVerified, true);
    assert.equal(verification.provenanceAssurance, 'AUTHENTIC_AND_LEDGER_CONFIRMED');
    assert.equal(verification.signerRecipient?.id, alice.id);
  });

  test('UI-FLOW-07: Modified receipt produces detailed failure diagnostics in verification report', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc1, [alice]);
    const aliceSession = await loginAlice();

    const decResult = await DistributionService.executeRecipientDecryption(pkg, alice, aliceSession);
    const receipt = await ReceiptService.generateReceipt({
      pkg,
      recipient: alice,
      decryptionEvent: decResult.decryptionEvent,
      watermarkPayload: decResult.watermarkPayload,
      blockHeight: decResult.blockHeight,
      session: aliceSession,
    });

    // Alter block height
    const tampered = { ...receipt, blockHeight: 999 };
    const verification = await ReceiptService.verifyReceipt(tampered);

    assert.equal(verification.valid, false);
    assert.equal(verification.signatureValid, false);
    assert.ok(verification.errors.length > 0);
    assert.ok(verification.errors.some((e) => e.includes('CryptographicVerificationFailed')));
    assert.equal(verification.provenanceAssurance, 'UNTRUSTED_OR_TAMPERED');
  });
});
