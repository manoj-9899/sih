import './setup';
import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  airGappedStorage,
  DB_NAME,
  DB_VERSION,
  STORES,
  AirGappedStorage,
} from '../src/storage/airGappedStorage';
import { AssignmentService } from '../src/services/assignmentService';
import { DistributionService } from '../src/services/distributionService';
import { sessionManager } from '../src/crypto/sessionManager';
import { createUnifiedEncryptedKeystore, unlockKeystoreRecord } from '../src/crypto/keystore';
import { airGappedLedger } from '../src/ledger/dlt';
import { generateRecipientPqcKeys, bytesToHex } from '../src/crypto/pqc';
import {
  Recipient,
  ClassifiedDocument,
  DocumentAssignment,
  RecipientNotification,
} from '../src/types';

describe('AEGIS-PQC: ASSIGNMENT & NOTIFICATION FOUNDATION (ASGN-01 to ASGN-25)', () => {
  let doc: ClassifiedDocument;
  let alice: Recipient;
  let bob: Recipient;
  let charlie: Recipient;

  beforeEach(async () => {
    await airGappedStorage.clearAll();
    await airGappedLedger.initGenesis();

    const aliceKeys = await generateRecipientPqcKeys();
    const bobKeys = await generateRecipientPqcKeys();
    const charlieKeys = await generateRecipientPqcKeys();

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
        keyFingerprint: aliceKeys.fingerprint,
      },
      createdAt: Date.now(),
    };

    bob = {
      id: 'REC-BOB-02',
      name: 'Agent Bob Stone',
      organization: 'Strategic Reconnaissance',
      role: 'Field Analyst',
      clearanceLevel: 'SECRET',
      avatarInitials: 'BS',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(bobKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(bobKeys.dsaPublicKey),
        keyFingerprint: bobKeys.fingerprint,
      },
      createdAt: Date.now(),
    };

    charlie = {
      id: 'REC-CHARLIE-03',
      name: 'Charlie Chen',
      organization: 'Cryptographic Logistics',
      role: 'Security Engineer',
      clearanceLevel: 'CONFIDENTIAL',
      avatarInitials: 'CC',
      status: 'AUTHORIZED',
      distributionStatus: 'AUTHORIZED',
      keys: {
        kemAlgorithm: 'ML-KEM-768',
        kemPublicKeyHex: bytesToHex(charlieKeys.kemPublicKey),
        dsaAlgorithm: 'ML-DSA-65',
        dsaPublicKeyHex: bytesToHex(charlieKeys.dsaPublicKey),
        keyFingerprint: charlieKeys.fingerprint,
      },
      createdAt: Date.now(),
    };

    doc = {
      id: 'DOC-PQC-STRAT-01',
      title: 'Orbital Reconnaissance Protocol Alpha',
      classification: 'TOP SECRET // SCI',
      caveats: 'NOFORN // ORCON',
      originatingOffice: 'Directorate of Aerospace Intelligence',
      summary: 'Automated satellite reconnaissance routing matrix.',
      rawText: 'RESTRICTED PAYLOAD: All telemetry channels must route via quantum-resistant proxy node 9.',
      visualPages: [],
      createdAt: Date.now(),
      fileSizeBytes: 2048,
      mimeType: 'text/plain',
      filename: 'orbital_protocol_alpha.txt',
    };
  });

  // =========================================================================
  // GROUP 1: INDEXEDDB MIGRATION (V1 -> V2 SCHEMA EVOLUTION)
  // =========================================================================

  test('MIG-01: Schema version is set to 2 with preserved database name', () => {
    assert.equal(DB_NAME, 'sih26237_airgap_store_v1');
    assert.equal(DB_VERSION, 2);
  });

  test('MIG-02: STORES registry contains both v1 stores and new v2 stores', () => {
    // V1 stores
    assert.equal(STORES.BLOCKS, 'blocks');
    assert.equal(STORES.RECIPIENTS, 'recipients');
    assert.equal(STORES.PACKAGES, 'packages');
    assert.equal(STORES.KEYSTORES, 'keystores');
    assert.equal(STORES.AUDIT_LOGS, 'audit_logs');
    // V2 stores
    assert.equal(STORES.ASSIGNMENTS, 'assignments');
    assert.equal(STORES.NOTIFICATIONS, 'notifications');
  });

  test('MIG-03: Non-destructive migration simulates existing v1 records and upgrades with new stores', () => {
    // Simulate v1 schema objects
    const mockV1Stores = new Set(['blocks', 'recipients', 'packages', 'keystores', 'audit_logs']);
    const createdStores: Record<string, { keyPath: string; indexes: Record<string, { keyPath: string; unique: boolean }> }> = {};

    const mockDb: any = {
      objectStoreNames: {
        contains: (name: string) => mockV1Stores.has(name) || name in createdStores,
      },
      createObjectStore: (name: string, options: { keyPath?: string; autoIncrement?: boolean }) => {
        const indexes: Record<string, { keyPath: string; unique: boolean }> = {};
        const store = {
          keyPath: options.keyPath || '',
          indexes,
          createIndex: (idxName: string, keyPath: string, opts: { unique: boolean }) => {
            indexes[idxName] = { keyPath, unique: opts.unique };
          },
          indexNames: {
            contains: (idxName: string) => idxName in indexes,
          },
        };
        createdStores[name] = store;
        return store;
      },
    };

    // Run upgrade handler logic
    const upgradeHandler = (db: typeof mockDb) => {
      // V1 checks
      if (!db.objectStoreNames.contains(STORES.BLOCKS)) {
        db.createObjectStore(STORES.BLOCKS, { keyPath: 'height' });
      }
      if (!db.objectStoreNames.contains(STORES.RECIPIENTS)) {
        db.createObjectStore(STORES.RECIPIENTS, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORES.PACKAGES)) {
        db.createObjectStore(STORES.PACKAGES, { keyPath: 'packageId' });
      }
      if (!db.objectStoreNames.contains(STORES.KEYSTORES)) {
        db.createObjectStore(STORES.KEYSTORES, { keyPath: 'keyId' });
      }
      if (!db.objectStoreNames.contains(STORES.AUDIT_LOGS)) {
        db.createObjectStore(STORES.AUDIT_LOGS, { autoIncrement: true });
      }

      // V2 upgrade: assignments & notifications
      if (!db.objectStoreNames.contains(STORES.ASSIGNMENTS)) {
        const asgnStore = db.createObjectStore(STORES.ASSIGNMENTS, { keyPath: 'assignmentId' });
        asgnStore.createIndex('recipientId', 'recipientId', { unique: false });
        asgnStore.createIndex('packageId', 'packageId', { unique: false });
        asgnStore.createIndex('distributionId', 'distributionId', { unique: false });
        asgnStore.createIndex('status', 'status', { unique: false });
        asgnStore.createIndex('createdAt', 'createdAt', { unique: false });
      }

      if (!db.objectStoreNames.contains(STORES.NOTIFICATIONS)) {
        const notifStore = db.createObjectStore(STORES.NOTIFICATIONS, { keyPath: 'notificationId' });
        notifStore.createIndex('recipientId', 'recipientId', { unique: false });
        notifStore.createIndex('assignmentId', 'assignmentId', { unique: false });
        notifStore.createIndex('type', 'type', { unique: false });
        notifStore.createIndex('read', 'read', { unique: false });
        notifStore.createIndex('createdAt', 'createdAt', { unique: false });
        notifStore.createIndex('packageId', 'packageId', { unique: false });
      }
    };

    upgradeHandler(mockDb);

    // Assert v1 stores were NOT re-created (they already existed)
    assert.equal('blocks' in createdStores, false);
    assert.equal('recipients' in createdStores, false);
    assert.equal('packages' in createdStores, false);

    // Assert v2 stores WERE created with correct keyPaths
    assert.equal('assignments' in createdStores, true);
    assert.equal(createdStores['assignments'].keyPath, 'assignmentId');
    assert.equal(createdStores['assignments'].indexes['recipientId'].unique, false);
    assert.equal(createdStores['assignments'].indexes['packageId'].unique, false);
    assert.equal(createdStores['assignments'].indexes['distributionId'].unique, false);
    assert.equal(createdStores['assignments'].indexes['status'].unique, false);
    assert.equal(createdStores['assignments'].indexes['createdAt'].unique, false);

    assert.equal('notifications' in createdStores, true);
    assert.equal(createdStores['notifications'].keyPath, 'notificationId');
    assert.equal(createdStores['notifications'].indexes['recipientId'].unique, false);
    assert.equal(createdStores['notifications'].indexes['assignmentId'].unique, false);
    assert.equal(createdStores['notifications'].indexes['type'].unique, false);
    assert.equal(createdStores['notifications'].indexes['read'].unique, false);
    assert.equal(createdStores['notifications'].indexes['createdAt'].unique, false);
  });

  // =========================================================================
  // GROUP 2: PERSISTENCE & CRUD OPERATIONS
  // =========================================================================

  test('PERSIST-01: Save and retrieve a single assignment', async () => {
    const assignment: DocumentAssignment = {
      assignmentId: 'ASGN-DIST-01-ALICE',
      distributionId: 'DIST-01',
      packageId: 'PKG-01',
      documentId: doc.id,
      documentTitle: doc.title,
      classification: doc.classification,
      fileSizeBytes: doc.fileSizeBytes,
      senderId: 'SNDR-01',
      senderName: 'Command Center',
      recipientId: alice.id,
      recipientName: alice.name,
      status: 'ASSIGNED',
      origin: 'LOCAL',
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    await airGappedStorage.saveAssignment(assignment);
    const retrieved = await airGappedStorage.getAssignment('ASGN-DIST-01-ALICE');

    assert.ok(retrieved);
    assert.equal(retrieved.assignmentId, 'ASGN-DIST-01-ALICE');
    assert.equal(retrieved.recipientId, alice.id);
    assert.equal(retrieved.status, 'ASSIGNED');
    assert.equal(retrieved.documentTitle, doc.title);
  });

  test('PERSIST-02: Batch save and query assignments by recipient, package, and distribution', async () => {
    const asgnAlice: DocumentAssignment = {
      assignmentId: 'ASGN-DIST-BATCH-ALICE',
      distributionId: 'DIST-BATCH',
      packageId: 'PKG-BATCH-99',
      documentId: doc.id,
      documentTitle: doc.title,
      classification: doc.classification,
      senderId: 'SNDR-01',
      recipientId: alice.id,
      status: 'ASSIGNED',
      origin: 'LOCAL',
      createdAt: 1000,
      updatedAt: 1000,
    };

    const asgnBob: DocumentAssignment = {
      assignmentId: 'ASGN-DIST-BATCH-BOB',
      distributionId: 'DIST-BATCH',
      packageId: 'PKG-BATCH-99',
      documentId: doc.id,
      documentTitle: doc.title,
      classification: doc.classification,
      senderId: 'SNDR-01',
      recipientId: bob.id,
      status: 'ASSIGNED',
      origin: 'LOCAL',
      createdAt: 2000,
      updatedAt: 2000,
    };

    await airGappedStorage.saveAssignments([asgnAlice, asgnBob]);

    const all = await airGappedStorage.getAssignments();
    assert.equal(all.length, 2);

    const forAlice = await airGappedStorage.getAssignmentsByRecipient(alice.id);
    assert.equal(forAlice.length, 1);
    assert.equal(forAlice[0].assignmentId, asgnAlice.assignmentId);

    const forBob = await airGappedStorage.getAssignmentsByRecipient(bob.id);
    assert.equal(forBob.length, 1);
    assert.equal(forBob[0].assignmentId, asgnBob.assignmentId);

    const forPkg = await airGappedStorage.getAssignmentsByPackage('PKG-BATCH-99');
    assert.equal(forPkg.length, 2);

    const forDist = await airGappedStorage.getAssignmentsByDistribution('DIST-BATCH');
    assert.equal(forDist.length, 2);
  });

  test('PERSIST-03: Assignment status transitions through full lifecycle', async () => {
    const assignmentId = 'ASGN-LIFECYCLE-01';
    await airGappedStorage.saveAssignment({
      assignmentId,
      distributionId: 'DIST-LIFE',
      documentId: doc.id,
      documentTitle: doc.title,
      classification: doc.classification,
      senderId: 'SNDR-01',
      recipientId: alice.id,
      status: 'ASSIGNED',
      origin: 'LOCAL',
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });

    // 1. Transition to PACKAGE_GENERATED
    const gen = await airGappedStorage.updateAssignmentStatus(assignmentId, 'PACKAGE_GENERATED', {
      packageId: 'PKG-GEN-01',
      packageGeneratedAt: Date.now(),
    });
    assert.equal(gen?.status, 'PACKAGE_GENERATED');
    assert.equal(gen?.packageId, 'PKG-GEN-01');

    // 2. Transition to DOWNLOADED
    const dl = await airGappedStorage.updateAssignmentStatus(assignmentId, 'DOWNLOADED', {
      downloadedAt: Date.now(),
    });
    assert.equal(dl?.status, 'DOWNLOADED');
    assert.ok(dl?.downloadedAt);

    // 3. Transition to DECRYPTED
    const dec = await airGappedStorage.updateAssignmentStatus(assignmentId, 'DECRYPTED', {
      decryptedAt: Date.now(),
      decryptionEventId: 'EVT-999',
      decryptionBlockHeight: 4,
    });
    assert.equal(dec?.status, 'DECRYPTED');
    assert.equal(dec?.decryptionEventId, 'EVT-999');
    assert.equal(dec?.decryptionBlockHeight, 4);

    // 4. Revocation
    const rev = await airGappedStorage.updateAssignmentStatus(assignmentId, 'REVOKED', {
      revokedAt: Date.now(),
      revocationReason: 'Security incident audit',
    });
    assert.equal(rev?.status, 'REVOKED');
    assert.equal(rev?.revocationReason, 'Security incident audit');
  });

  test('PERSIST-04: Notifications CRUD, recipient filtering, and read marking', async () => {
    const nAlice1: RecipientNotification = {
      notificationId: 'NOTIF-A-1',
      recipientId: alice.id,
      assignmentId: 'ASGN-1',
      type: 'ASSIGNMENT_CREATED',
      title: 'New Assignment',
      message: 'You have a document.',
      timestamp: 100,
      read: false,
    };
    const nAlice2: RecipientNotification = {
      notificationId: 'NOTIF-A-2',
      recipientId: alice.id,
      assignmentId: 'ASGN-2',
      type: 'PACKAGE_READY',
      title: 'Package Ready',
      message: 'Ready to decrypt.',
      timestamp: 200,
      read: false,
    };
    const nBob: RecipientNotification = {
      notificationId: 'NOTIF-B-1',
      recipientId: bob.id,
      assignmentId: 'ASGN-3',
      type: 'ASSIGNMENT_CREATED',
      title: 'Bob Assignment',
      message: 'Bob document.',
      timestamp: 150,
      read: false,
    };

    await airGappedStorage.saveNotifications([nAlice1, nAlice2, nBob]);

    const aliceNotifs = await airGappedStorage.getNotificationsByRecipient(alice.id);
    assert.equal(aliceNotifs.length, 2);
    // Should be sorted descending by timestamp
    assert.equal(aliceNotifs[0].notificationId, 'NOTIF-A-2');
    assert.equal(aliceNotifs[1].notificationId, 'NOTIF-A-1');

    // Mark single notification read
    const marked = await airGappedStorage.markNotificationAsRead('NOTIF-A-1', alice.id);
    assert.equal(marked?.read, true);
    assert.ok(marked?.readAt);

    // Verify Bob's notification is still unread
    const bobNotifs = await airGappedStorage.getNotificationsByRecipient(bob.id);
    assert.equal(bobNotifs[0].read, false);

    // Mark all Alice notifications as read
    await airGappedStorage.markAllNotificationsAsRead(alice.id);
    const updatedAliceNotifs = await airGappedStorage.getNotificationsByRecipient(alice.id);
    assert.equal(updatedAliceNotifs.every((n) => n.read), true);
  });

  // =========================================================================
  // GROUP 3: IDEMPOTENCY
  // =========================================================================

  test('IDEMP-01: Re-calling createAssignmentsForDistribution does not duplicate records', async () => {
    const distributionId = 'DIST-IDEMP-TEST-01';

    // First call
    const run1 = await AssignmentService.createAssignmentsForDistribution({
      doc,
      recipients: [alice, bob],
      distributionId,
    });
    assert.equal(run1.length, 2);

    const initialAssignments = await airGappedStorage.getAssignmentsByDistribution(distributionId);
    assert.equal(initialAssignments.length, 2);

    // Second identical call
    const run2 = await AssignmentService.createAssignmentsForDistribution({
      doc,
      recipients: [alice, bob],
      distributionId,
    });
    assert.equal(run2.length, 2);

    const afterSecondCall = await airGappedStorage.getAssignmentsByDistribution(distributionId);
    assert.equal(afterSecondCall.length, 2, 'Must not duplicate assignments');
  });

  test('IDEMP-02: Idempotent calls do not overwrite advanced lifecycle state (e.g. DECRYPTED)', async () => {
    const distributionId = 'DIST-IDEMP-PRESERVE-01';

    await AssignmentService.createAssignmentsForDistribution({
      doc,
      recipients: [alice],
      distributionId,
      packageId: 'PKG-PRESERVE-01',
    });

    // Advance status to DECRYPTED
    const asgnId = AssignmentService.computeAssignmentId(distributionId, alice.id);
    await airGappedStorage.updateAssignmentStatus(asgnId, 'DECRYPTED', {
      decryptedAt: 55555,
      decryptionEventId: 'EVT-PRESERVED',
      decryptionBlockHeight: 8,
    });

    // Re-run distribution with packageId
    await AssignmentService.createAssignmentsForDistribution({
      doc,
      recipients: [alice],
      distributionId,
      packageId: 'PKG-PRESERVE-01',
    });

    const check = await airGappedStorage.getAssignment(asgnId);
    assert.equal(check?.status, 'DECRYPTED', 'Must not downgrade DECRYPTED status back to PACKAGE_GENERATED or ASSIGNED');
    assert.equal(check?.decryptionEventId, 'EVT-PRESERVED');
    assert.equal(check?.decryptionBlockHeight, 8);
  });

  // =========================================================================
  // GROUP 4: STRICT RECIPIENT ISOLATION
  // =========================================================================

  test('ISOL-01: Recipients can only query their own assignments', async () => {
    const distId = 'DIST-ISOLATION-01';
    await AssignmentService.createAssignmentsForDistribution({
      doc,
      recipients: [alice, bob],
      distributionId: distId,
    });

    const aliceAssignments = await AssignmentService.getAssignmentsForRecipient(alice.id);
    const bobAssignments = await AssignmentService.getAssignmentsForRecipient(bob.id);
    const charlieAssignments = await AssignmentService.getAssignmentsForRecipient(charlie.id);

    // Alice sees only hers
    assert.equal(aliceAssignments.length, 1);
    assert.equal(aliceAssignments[0].recipientId, alice.id);

    // Bob sees only his
    assert.equal(bobAssignments.length, 1);
    assert.equal(bobAssignments[0].recipientId, bob.id);

    // Charlie has none
    assert.equal(charlieAssignments.length, 0);
  });

  test('ISOL-02: Recipients can only query their own targeted notifications', async () => {
    const distId = 'DIST-ISOLATION-NOTIFS-01';
    await AssignmentService.createAssignmentsForDistribution({
      doc,
      recipients: [alice, bob],
      distributionId: distId,
    });

    const aliceNotifs = await AssignmentService.getNotificationsForRecipient(alice.id);
    const bobNotifs = await AssignmentService.getNotificationsForRecipient(bob.id);
    const charlieNotifs = await AssignmentService.getNotificationsForRecipient(charlie.id);

    assert.equal(aliceNotifs.length, 1);
    assert.equal(aliceNotifs[0].recipientId, alice.id);

    assert.equal(bobNotifs.length, 1);
    assert.equal(bobNotifs[0].recipientId, bob.id);

    assert.equal(charlieNotifs.length, 0);
  });

  test('ISOL-03: Unauthorized recipient cannot mark another recipient notification as read', async () => {
    const distId = 'DIST-ISOL-SECURITY-01';
    await AssignmentService.createAssignmentsForDistribution({
      doc,
      recipients: [alice, bob],
      distributionId: distId,
    });

    const bobNotifs = await AssignmentService.getNotificationsForRecipient(bob.id);
    const bobNotifId = bobNotifs[0].notificationId;

    // Alice tries to mark Bob's notification as read
    await assert.rejects(
      async () => {
        await AssignmentService.markNotificationRead(bobNotifId, alice.id);
      },
      /Unauthorized/
    );

    // Bob can mark his own notification as read
    const marked = await AssignmentService.markNotificationRead(bobNotifId, bob.id);
    assert.equal(marked?.read, true);
  });

  // =========================================================================
  // GROUP 5: END-TO-END WORKFLOW INTEGRATION
  // =========================================================================

  test('E2E-01: DistributionService.createEncryptedPackage automatically provisions assignments & notifications', async () => {
    const pkg = await DistributionService.createEncryptedPackage(doc, [alice, bob], 'Directorate of Strategic Operations');
    assert.ok(pkg.packageId);

    // Check assignments were created for both Alice and Bob
    const aliceAssignments = await AssignmentService.getAssignmentsForRecipient(alice.id);
    assert.equal(aliceAssignments.length, 1);
    assert.equal(aliceAssignments[0].packageId, pkg.packageId);
    assert.equal(aliceAssignments[0].status, 'PACKAGE_GENERATED');

    const bobAssignments = await AssignmentService.getAssignmentsForRecipient(bob.id);
    assert.equal(bobAssignments.length, 1);
    assert.equal(bobAssignments[0].packageId, pkg.packageId);
    assert.equal(bobAssignments[0].status, 'PACKAGE_GENERATED');

    // Check notifications were delivered to each recipient
    const aliceNotifs = await AssignmentService.getNotificationsForRecipient(alice.id);
    assert.equal(aliceNotifs.length, 1);
    assert.equal(aliceNotifs[0].type, 'PACKAGE_READY');
    assert.equal(aliceNotifs[0].packageId, pkg.packageId);

    const bobNotifs = await AssignmentService.getNotificationsForRecipient(bob.id);
    assert.equal(bobNotifs.length, 1);
    assert.equal(bobNotifs[0].type, 'PACKAGE_READY');
  });

  test('E2E-02: DistributionService.executeRecipientDecryption updates assignment status to DECRYPTED with DLT block anchor', async () => {
    const alicePass = 'AirGap#Test#2026';
    const aliceKeys = await generateRecipientPqcKeys();
    const aliceKeystore = await createUnifiedEncryptedKeystore(
      alice.id,
      aliceKeys.fingerprint,
      aliceKeys.kemSecretKey,
      aliceKeys.dsaSecretKey,
      alicePass
    );
    await airGappedStorage.saveKeystore(aliceKeystore);

    const aliceRecipient: Recipient = {
      ...alice,
      keys: {
        ...alice.keys,
        kemPublicKeyHex: bytesToHex(aliceKeys.kemPublicKey),
        dsaPublicKeyHex: bytesToHex(aliceKeys.dsaPublicKey),
        encryptedKeystore: aliceKeystore,
        keyFingerprint: aliceKeys.fingerprint,
      },
    };
    airGappedLedger.registerRecipient(aliceRecipient);
    await airGappedStorage.saveRecipient(aliceRecipient);

    // 1. Create package with Alice as recipient
    const reEncryptedPkg = await DistributionService.createEncryptedPackage(doc, [aliceRecipient], 'Directorate of Strategic Operations');

    // 2. Unlock keystore and establish active session
    const unlockedAlice = await unlockKeystoreRecord(aliceKeystore, alicePass);
    assert.ok(unlockedAlice);
    const sessionAlice = sessionManager.startSession(aliceRecipient, unlockedAlice);
    assert.ok(sessionAlice);

    // 3. Decrypt as Alice
    const decryptResult = await DistributionService.executeRecipientDecryption(
      reEncryptedPkg,
      aliceRecipient,
      sessionAlice
    );

    assert.ok(decryptResult.decryptionEvent);
    assert.ok(decryptResult.blockHeight > 0);

    // 3. Verify assignment status transitioned to DECRYPTED
    const assignments = await AssignmentService.getAssignmentsForRecipient(alice.id);
    const aliceAsgn = assignments.find((a) => a.packageId === reEncryptedPkg.packageId);
    assert.ok(aliceAsgn);
    assert.equal(aliceAsgn.status, 'DECRYPTED');
    assert.equal(aliceAsgn.decryptionEventId, decryptResult.decryptionEvent.eventId);
    assert.equal(aliceAsgn.decryptionBlockHeight, decryptResult.blockHeight);

    // 4. Verify targeted DOCUMENT_DECRYPTED notification was generated
    const notifs = await AssignmentService.getNotificationsForRecipient(alice.id);
    const decNotif = notifs.find((n) => n.type === 'DOCUMENT_DECRYPTED');
    assert.ok(decNotif);
    assert.equal(decNotif.packageId, reEncryptedPkg.packageId);
  });

  test('E2E-03: Revoking an assignment generates ACCESS_REVOKED notification targeted to recipient', async () => {
    const distId = 'DIST-REVOKE-TEST';
    const [asgn] = await AssignmentService.createAssignmentsForDistribution({
      doc,
      recipients: [bob],
      distributionId: distId,
      packageId: 'PKG-REVOKE-01',
    });

    const revoked = await AssignmentService.revokeAssignment(asgn.assignmentId, 'Security clearance expired');
    assert.equal(revoked?.status, 'REVOKED');
    assert.equal(revoked?.revocationReason, 'Security clearance expired');

    // Check Bob's notifications
    const bobNotifs = await AssignmentService.getNotificationsForRecipient(bob.id);
    const revNotif = bobNotifs.find((n) => n.type === 'ACCESS_REVOKED');
    assert.ok(revNotif);
    assert.equal(revNotif.title, 'Document Access Revoked');
    assert.match(revNotif.message, /Security clearance expired/);
  });
});
