/**
 * Air-Gapped Persistent Storage Adapter using IndexedDB with fallback to localStorage.
 * Enables DLT blockchain state, recipient keystores, encrypted packages,
 * assignments, and notifications to survive browser refreshes and system reboots
 * in an isolated offline environment.
 * 
 * Database Version: 2 (Non-destructive upgrade from v1)
 */

import { ForensicCaseRecord, DocumentAssignment, RecipientNotification, AssignmentStatus } from '../types';

export const DB_NAME = 'sih26237_airgap_store_v1';
export const DB_VERSION = 2;

export const STORES = {
  BLOCKS: 'blocks',
  RECIPIENTS: 'recipients',
  PACKAGES: 'packages',
  KEYSTORES: 'keystores',
  AUDIT_LOGS: 'audit_logs',
  ASSIGNMENTS: 'assignments',
  NOTIFICATIONS: 'notifications',
} as const;

export class AirGappedStorage {
  private db: IDBDatabase | null = null;
  private isReadyPromise: Promise<boolean>;

  constructor() {
    this.isReadyPromise = this.initDB();
  }

  /**
   * Initializes IndexedDB with non-destructive version 1 -> version 2 migration.
   * Handles blocked upgrades, aborts, and transactional commit guarantees.
   */
  private async initDB(): Promise<boolean> {
    if (typeof window === 'undefined' || !window.indexedDB) {
      console.warn('[AirGappedStorage] IndexedDB unavailable, using memory/localStorage fallback.');
      return false;
    }

    return new Promise((resolve) => {
      try {
        const request = window.indexedDB.open(DB_NAME, DB_VERSION);

        request.onblocked = () => {
          console.warn('[AirGappedStorage] IndexedDB v2 upgrade blocked. Please close open connections/tabs.');
        };

        request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
          const db = (event.target as IDBOpenDBRequest).result;
          const oldVersion = event.oldVersion;

          // Version 1 object stores (preserved without clearing or recreation)
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

          // Version 2 object stores: Assignments & Notifications
          if (!db.objectStoreNames.contains(STORES.ASSIGNMENTS)) {
            const assignmentStore = db.createObjectStore(STORES.ASSIGNMENTS, { keyPath: 'assignmentId' });
            assignmentStore.createIndex('recipientId', 'recipientId', { unique: false });
            assignmentStore.createIndex('packageId', 'packageId', { unique: false });
            assignmentStore.createIndex('distributionId', 'distributionId', { unique: false });
            assignmentStore.createIndex('status', 'status', { unique: false });
            assignmentStore.createIndex('createdAt', 'createdAt', { unique: false });
          } else {
            const tx = (event.target as IDBOpenDBRequest).transaction;
            if (tx) {
              const store = tx.objectStore(STORES.ASSIGNMENTS);
              if (!store.indexNames.contains('recipientId')) store.createIndex('recipientId', 'recipientId', { unique: false });
              if (!store.indexNames.contains('packageId')) store.createIndex('packageId', 'packageId', { unique: false });
              if (!store.indexNames.contains('distributionId')) store.createIndex('distributionId', 'distributionId', { unique: false });
              if (!store.indexNames.contains('status')) store.createIndex('status', 'status', { unique: false });
              if (!store.indexNames.contains('createdAt')) store.createIndex('createdAt', 'createdAt', { unique: false });
            }
          }

          if (!db.objectStoreNames.contains(STORES.NOTIFICATIONS)) {
            const notificationStore = db.createObjectStore(STORES.NOTIFICATIONS, { keyPath: 'notificationId' });
            notificationStore.createIndex('recipientId', 'recipientId', { unique: false });
            notificationStore.createIndex('assignmentId', 'assignmentId', { unique: false });
            notificationStore.createIndex('type', 'type', { unique: false });
            notificationStore.createIndex('read', 'read', { unique: false });
            notificationStore.createIndex('createdAt', 'createdAt', { unique: false });
            notificationStore.createIndex('packageId', 'packageId', { unique: false });
          } else {
            const tx = (event.target as IDBOpenDBRequest).transaction;
            if (tx) {
              const store = tx.objectStore(STORES.NOTIFICATIONS);
              if (!store.indexNames.contains('recipientId')) store.createIndex('recipientId', 'recipientId', { unique: false });
              if (!store.indexNames.contains('assignmentId')) store.createIndex('assignmentId', 'assignmentId', { unique: false });
              if (!store.indexNames.contains('type')) store.createIndex('type', 'type', { unique: false });
              if (!store.indexNames.contains('read')) store.createIndex('read', 'read', { unique: false });
              if (!store.indexNames.contains('createdAt')) store.createIndex('createdAt', 'createdAt', { unique: false });
              if (!store.indexNames.contains('packageId')) store.createIndex('packageId', 'packageId', { unique: false });
            }
          }

          console.info(`[AirGappedStorage] Migrated database schema from v${oldVersion} to v${DB_VERSION}`);
        };

        request.onsuccess = () => {
          this.db = request.result;
          resolve(true);
        };

        request.onerror = () => {
          console.warn('[AirGappedStorage] IndexedDB open error, falling back:', request.error);
          resolve(false);
        };
      } catch (err) {
        console.warn('[AirGappedStorage] Initialization failed:', err);
        resolve(false);
      }
    });
  }

  public async isReady(): Promise<boolean> {
    return this.isReadyPromise;
  }

  /**
   * Helper that executes an IndexedDB write inside a transaction and guarantees
   * that write errors or aborts reject the promise rather than returning early.
   */
  private async executeTxWrite(
    storeName: string,
    operation: (store: IDBObjectStore) => void
  ): Promise<void> {
    if (!this.db) {
      throw new Error('Database connection not established.');
    }
    return new Promise<void>((resolve, reject) => {
      try {
        const tx = this.db!.transaction(storeName, 'readwrite');
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error || new Error(`IndexedDB transaction failed on ${storeName}`));
        tx.onabort = () => reject(tx.error || new Error(`IndexedDB transaction aborted on ${storeName}`));
        const store = tx.objectStore(storeName);
        operation(store);
      } catch (err) {
        reject(err);
      }
    });
  }

  // --- BLOCKS ---
  public async saveBlocks(blocks: any[]): Promise<void> {
    await this.isReady();
    if (this.db) {
      await this.executeTxWrite(STORES.BLOCKS, (store) => {
        for (const b of blocks) {
          store.put(b);
        }
      });
    } else {
      localStorage.setItem('sih_dlt_blocks', JSON.stringify(blocks));
    }
  }

  public async getBlocks(): Promise<any[] | null> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve) => {
        const tx = this.db!.transaction(STORES.BLOCKS, 'readonly');
        const store = tx.objectStore(STORES.BLOCKS);
        const req = store.getAll();
        req.onsuccess = () => {
          const res = req.result;
          resolve(res && res.length > 0 ? res.sort((a, b) => a.height - b.height) : null);
        };
        req.onerror = () => resolve(null);
      });
    } else {
      const item = localStorage.getItem('sih_dlt_blocks');
      return item ? JSON.parse(item) : null;
    }
  }

  public async clearBlocks(): Promise<void> {
    await this.isReady();
    if (this.db) {
      await this.executeTxWrite(STORES.BLOCKS, (store) => store.clear());
    }
    localStorage.removeItem('sih_dlt_blocks');
  }

  // --- PACKAGES ---
  public async savePackage(pkg: any): Promise<void> {
    await this.isReady();
    if (this.db) {
      await this.executeTxWrite(STORES.PACKAGES, (store) => store.put(pkg));
    } else {
      const existing = (await this.getPackages()) || [];
      const updated = existing.filter((p) => p.packageId !== pkg.packageId).concat(pkg);
      localStorage.setItem('sih_packages', JSON.stringify(updated));
    }
  }

  public async getPackages(): Promise<any[] | null> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve) => {
        const tx = this.db!.transaction(STORES.PACKAGES, 'readonly');
        const req = tx.objectStore(STORES.PACKAGES).getAll();
        req.onsuccess = () => resolve(req.result.length > 0 ? req.result : null);
        req.onerror = () => resolve(null);
      });
    } else {
      const item = localStorage.getItem('sih_packages');
      return item ? JSON.parse(item) : null;
    }
  }

  public async clearPackages(): Promise<void> {
    await this.isReady();
    if (this.db) {
      await this.executeTxWrite(STORES.PACKAGES, (store) => store.clear());
    }
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('sih_packages');
    }
  }

  // --- KEYSTORES ---
  public async saveKeystore(keystore: { keyId: string; [key: string]: any }): Promise<void> {
    await this.isReady();
    if (this.db) {
      await this.executeTxWrite(STORES.KEYSTORES, (store) => store.put(keystore));
    } else {
      const allStr = localStorage.getItem('sih_keystores');
      const all = allStr ? JSON.parse(allStr) : {};
      all[keystore.keyId] = keystore;
      localStorage.setItem('sih_keystores', JSON.stringify(all));
    }
  }

  public async getKeystore(keyId: string): Promise<any | null> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve) => {
        const tx = this.db!.transaction(STORES.KEYSTORES, 'readonly');
        const req = tx.objectStore(STORES.KEYSTORES).get(keyId);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => resolve(null);
      });
    } else {
      const allStr = localStorage.getItem('sih_keystores');
      const all = allStr ? JSON.parse(allStr) : {};
      return all[keyId] || null;
    }
  }

  // --- RECIPIENTS ---
  public async saveRecipients(recipients: any[]): Promise<void> {
    await this.isReady();
    if (this.db) {
      await this.executeTxWrite(STORES.RECIPIENTS, (store) => {
        for (const r of recipients) {
          store.put(r);
        }
      });
    } else {
      localStorage.setItem('sih_recipients', JSON.stringify(recipients));
    }
  }

  public async saveRecipient(recipient: any): Promise<void> {
    const existing = (await this.getRecipients()) || [];
    const updated = existing.filter((r) => r.id !== recipient.id).concat(recipient);
    await this.saveRecipients(updated);
  }

  public async getRecipients(): Promise<any[] | null> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve) => {
        const tx = this.db!.transaction(STORES.RECIPIENTS, 'readonly');
        const req = tx.objectStore(STORES.RECIPIENTS).getAll();
        req.onsuccess = () => resolve(req.result.length > 0 ? req.result : null);
        req.onerror = () => resolve(null);
      });
    } else {
      const item = localStorage.getItem('sih_recipients');
      return item ? JSON.parse(item) : null;
    }
  }

  // --- FORENSIC CASES HISTORY ---
  public async saveForensicCase(caseRecord: ForensicCaseRecord): Promise<void> {
    try {
      const all = await this.getForensicCases();
      const updated = [caseRecord, ...all.filter((c) => c.caseId !== caseRecord.caseId)].slice(0, 50);
      if (typeof window !== 'undefined' && window.localStorage) {
        localStorage.setItem('sih_forensic_cases', JSON.stringify(updated));
      }
    } catch (e) {
      console.warn('[AirGappedStorage] Failed to save forensic case:', e);
    }
  }

  public async getForensicCases(): Promise<ForensicCaseRecord[]> {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        const item = localStorage.getItem('sih_forensic_cases');
        if (item) {
          return JSON.parse(item) as ForensicCaseRecord[];
        }
      }
    } catch (e) {
      console.warn('[AirGappedStorage] Failed to load forensic cases:', e);
    }
    return [];
  }

  public async clearForensicCases(): Promise<void> {
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('sih_forensic_cases');
    }
  }

  // --- ATTRIBUTION CERTIFICATES ---
  public async saveAttributionCertificate(cert: any): Promise<void> {
    try {
      const all = await this.getAttributionCertificates();
      const updated = [cert, ...all.filter((c: any) => c.certificateId !== cert.certificateId)].slice(0, 50);
      if (typeof window !== 'undefined' && window.localStorage) {
        localStorage.setItem('sih_attribution_certificates', JSON.stringify(updated));
      }
    } catch (e) {
      console.warn('[AirGappedStorage] Failed to save attribution certificate:', e);
    }
  }

  public async getAttributionCertificates(): Promise<any[]> {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        const item = localStorage.getItem('sih_attribution_certificates');
        if (item) {
          return JSON.parse(item);
        }
      }
    } catch (e) {
      console.warn('[AirGappedStorage] Failed to load attribution certificates:', e);
    }
    return [];
  }

  public async getAttributionCertificate(certId: string): Promise<any | null> {
    const all = await this.getAttributionCertificates();
    return all.find((c: any) => c.certificateId === certId || c.caseId === certId) || null;
  }

  public async clearAttributionCertificates(): Promise<void> {
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('sih_attribution_certificates');
    }
  }

  // --- PACKAGE & SECURITY AUDIT LOGS ---
  public async saveAuditEvent(event: any): Promise<void> {
    await this.isReady();
    if (this.db) {
      try {
        await this.executeTxWrite(STORES.AUDIT_LOGS, (store) => store.add(event));
      } catch (err) {
        console.warn('[AirGappedStorage] Failed to save audit log to IDB:', err);
      }
    }
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const item = localStorage.getItem('sih_package_audit_logs');
        const list = item ? JSON.parse(item) : [];
        const filtered = list.filter((e: any) => e.eventId !== event.eventId);
        filtered.push(event);
        localStorage.setItem('sih_package_audit_logs', JSON.stringify(filtered.slice(-500)));
      } catch (e) {
        console.warn('[AirGappedStorage] Failed to save audit log to localStorage:', e);
      }
    }
  }

  public async getAuditEvents(): Promise<any[]> {
    await this.isReady();
    if (this.db) {
      try {
        const idbEvents: any[] = await new Promise((resolve) => {
          const tx = this.db!.transaction(STORES.AUDIT_LOGS, 'readonly');
          const req = tx.objectStore(STORES.AUDIT_LOGS).getAll();
          req.onsuccess = () => resolve(req.result || []);
          req.onerror = () => resolve([]);
        });
        if (idbEvents && idbEvents.length > 0) {
          return idbEvents.sort((a, b) => (a.timestampEpochMs || a.timestamp || 0) - (b.timestampEpochMs || b.timestamp || 0));
        }
      } catch (e) {
        console.warn('[AirGappedStorage] IDB audit retrieval fallback:', e);
      }
    }
    if (typeof window !== 'undefined' && window.localStorage) {
      const item = localStorage.getItem('sih_package_audit_logs');
      const list = item ? JSON.parse(item) : [];
      return list.sort((a: any, b: any) => (a.timestampEpochMs || a.timestamp || 0) - (b.timestampEpochMs || b.timestamp || 0));
    }
    return [];
  }

  public async getAuditEventById(eventId: string): Promise<any | null> {
    const all = await this.getAuditEvents();
    return all.find((e: any) => e.eventId === eventId) || null;
  }

  public async clearAuditEvents(): Promise<void> {
    await this.isReady();
    if (this.db) {
      try {
        await this.executeTxWrite(STORES.AUDIT_LOGS, (store) => store.clear());
      } catch (e) {
        console.warn('[AirGappedStorage] Failed to clear audit logs from IDB:', e);
      }
    }
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('sih_package_audit_logs');
    }
  }

  // --- SECURITY INCIDENTS (NAMESPACED PERSISTENCE) ---
  public async saveIncident(incident: any): Promise<void> {
    await this.isReady();
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const raw = localStorage.getItem('sih_security_incidents_v1');
        const list = raw ? JSON.parse(raw) : [];
        const filtered = list.filter((item: any) => item.incidentId !== incident.incidentId);
        filtered.push(incident);
        localStorage.setItem('sih_security_incidents_v1', JSON.stringify(filtered.slice(-200)));
      } catch (e) {
        console.warn('[AirGappedStorage] Failed to save incident to storage:', e);
      }
    }
  }

  public async getIncidents(): Promise<any[]> {
    await this.isReady();
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const raw = localStorage.getItem('sih_security_incidents_v1');
        return raw ? JSON.parse(raw) : [];
      } catch (e) {
        console.warn('[AirGappedStorage] Failed to retrieve incidents:', e);
      }
    }
    return [];
  }

  public async clearIncidents(): Promise<void> {
    await this.isReady();
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('sih_security_incidents_v1');
    }
  }

  // --- FORENSIC DOSSIERS ---
  public async saveForensicDossier(dossier: any): Promise<void> {
    await this.isReady();
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const raw = localStorage.getItem('sih_forensic_dossiers_v1');
        const list = raw ? JSON.parse(raw) : [];
        const filtered = list.filter((item: any) => item.dossierId !== dossier.dossierId);
        filtered.push(dossier);
        localStorage.setItem('sih_forensic_dossiers_v1', JSON.stringify(filtered.slice(-100)));
      } catch (e) {
        console.warn('[AirGappedStorage] Failed to save dossier to storage:', e);
      }
    }
  }

  public async getForensicDossiers(): Promise<any[]> {
    await this.isReady();
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const raw = localStorage.getItem('sih_forensic_dossiers_v1');
        return raw ? JSON.parse(raw) : [];
      } catch (e) {
        console.warn('[AirGappedStorage] Failed to retrieve dossiers:', e);
      }
    }
    return [];
  }

  public async getForensicDossier(dossierId: string): Promise<any | null> {
    const all = await this.getForensicDossiers();
    return all.find((d: any) => d.dossierId === dossierId || d.sourceIncidentId === dossierId) || null;
  }

  public async clearForensicDossiers(): Promise<void> {
    await this.isReady();
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('sih_forensic_dossiers_v1');
    }
  }

  // =========================================================================
  // --- ASSIGNMENTS (V2 SCHEMA PERSISTENCE) ---
  // =========================================================================

  public async saveAssignment(assignment: DocumentAssignment): Promise<void> {
    await this.isReady();
    if (this.db) {
      await this.executeTxWrite(STORES.ASSIGNMENTS, (store) => {
        store.put(assignment);
      });
    } else {
      const existing = (await this.getAssignments()) || [];
      const updated = existing.filter((a) => a.assignmentId !== assignment.assignmentId).concat(assignment);
      localStorage.setItem('sih_assignments_v1', JSON.stringify(updated));
    }
  }

  public async saveAssignments(assignments: DocumentAssignment[]): Promise<void> {
    await this.isReady();
    if (assignments.length === 0) return;
    if (this.db) {
      await this.executeTxWrite(STORES.ASSIGNMENTS, (store) => {
        for (const a of assignments) {
          store.put(a);
        }
      });
    } else {
      const existing = (await this.getAssignments()) || [];
      const map = new Map<string, DocumentAssignment>();
      for (const a of existing) {
        map.set(a.assignmentId, a);
      }
      for (const a of assignments) {
        map.set(a.assignmentId, a);
      }
      localStorage.setItem('sih_assignments_v1', JSON.stringify(Array.from(map.values())));
    }
  }

  public async getAssignment(assignmentId: string): Promise<DocumentAssignment | null> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve, reject) => {
        try {
          const tx = this.db!.transaction(STORES.ASSIGNMENTS, 'readonly');
          const store = tx.objectStore(STORES.ASSIGNMENTS);
          const req = store.get(assignmentId);
          req.onsuccess = () => resolve(req.result || null);
          req.onerror = () => reject(req.error || new Error(`Failed to get assignment ${assignmentId}`));
        } catch (err) {
          reject(err);
        }
      });
    } else {
      const all = await this.getAssignments();
      return all.find((a) => a.assignmentId === assignmentId) || null;
    }
  }

  public async getAssignments(): Promise<DocumentAssignment[]> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve, reject) => {
        try {
          const tx = this.db!.transaction(STORES.ASSIGNMENTS, 'readonly');
          const store = tx.objectStore(STORES.ASSIGNMENTS);
          const req = store.getAll();
          req.onsuccess = () => {
            const list = (req.result || []) as DocumentAssignment[];
            resolve(list.sort((a, b) => b.createdAt - a.createdAt));
          };
          req.onerror = () => reject(req.error || new Error('Failed to retrieve assignments'));
        } catch (err) {
          reject(err);
        }
      });
    } else {
      const raw = localStorage.getItem('sih_assignments_v1');
      const list = raw ? (JSON.parse(raw) as DocumentAssignment[]) : [];
      return list.sort((a, b) => b.createdAt - a.createdAt);
    }
  }

  public async getAssignmentsByRecipient(recipientId: string): Promise<DocumentAssignment[]> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve, reject) => {
        try {
          const tx = this.db!.transaction(STORES.ASSIGNMENTS, 'readonly');
          const store = tx.objectStore(STORES.ASSIGNMENTS);
          const index = store.index('recipientId');
          const req = index.getAll(recipientId);
          req.onsuccess = () => {
            const list = (req.result || []) as DocumentAssignment[];
            resolve(list.sort((a, b) => b.createdAt - a.createdAt));
          };
          req.onerror = () => reject(req.error || new Error(`Failed to query assignments for recipient ${recipientId}`));
        } catch (err) {
          reject(err);
        }
      });
    } else {
      const all = await this.getAssignments();
      return all.filter((a) => a.recipientId === recipientId).sort((a, b) => b.createdAt - a.createdAt);
    }
  }

  public async getAssignmentsByPackage(packageId: string): Promise<DocumentAssignment[]> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve, reject) => {
        try {
          const tx = this.db!.transaction(STORES.ASSIGNMENTS, 'readonly');
          const store = tx.objectStore(STORES.ASSIGNMENTS);
          const index = store.index('packageId');
          const req = index.getAll(packageId);
          req.onsuccess = () => resolve((req.result || []) as DocumentAssignment[]);
          req.onerror = () => reject(req.error || new Error(`Failed to query assignments for package ${packageId}`));
        } catch (err) {
          reject(err);
        }
      });
    } else {
      const all = await this.getAssignments();
      return all.filter((a) => a.packageId === packageId);
    }
  }

  public async getAssignmentsByDistribution(distributionId: string): Promise<DocumentAssignment[]> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve, reject) => {
        try {
          const tx = this.db!.transaction(STORES.ASSIGNMENTS, 'readonly');
          const store = tx.objectStore(STORES.ASSIGNMENTS);
          const index = store.index('distributionId');
          const req = index.getAll(distributionId);
          req.onsuccess = () => resolve((req.result || []) as DocumentAssignment[]);
          req.onerror = () => reject(req.error || new Error(`Failed to query assignments for distribution ${distributionId}`));
        } catch (err) {
          reject(err);
        }
      });
    } else {
      const all = await this.getAssignments();
      return all.filter((a) => a.distributionId === distributionId);
    }
  }

  public async updateAssignmentStatus(
    assignmentId: string,
    status: AssignmentStatus,
    extra: Partial<DocumentAssignment> = {}
  ): Promise<DocumentAssignment | null> {
    const existing = await this.getAssignment(assignmentId);
    if (!existing) {
      return null;
    }
    const updated: DocumentAssignment = {
      ...existing,
      ...extra,
      status,
      updatedAt: Date.now(),
    };
    await this.saveAssignment(updated);
    return updated;
  }

  public async clearAssignments(): Promise<void> {
    await this.isReady();
    if (this.db) {
      await this.executeTxWrite(STORES.ASSIGNMENTS, (store) => store.clear());
    }
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('sih_assignments_v1');
    }
  }

  // =========================================================================
  // --- NOTIFICATIONS (V2 SCHEMA PERSISTENCE) ---
  // =========================================================================

  public async saveNotification(notification: RecipientNotification): Promise<void> {
    await this.isReady();
    if (this.db) {
      await this.executeTxWrite(STORES.NOTIFICATIONS, (store) => {
        store.put(notification);
      });
    } else {
      const existing = (await this.getNotifications()) || [];
      const updated = existing.filter((n) => n.notificationId !== notification.notificationId).concat(notification);
      localStorage.setItem('sih_notifications_v1', JSON.stringify(updated));
    }
  }

  public async saveNotifications(notifications: RecipientNotification[]): Promise<void> {
    await this.isReady();
    if (notifications.length === 0) return;
    if (this.db) {
      await this.executeTxWrite(STORES.NOTIFICATIONS, (store) => {
        for (const n of notifications) {
          store.put(n);
        }
      });
    } else {
      const existing = (await this.getNotifications()) || [];
      const map = new Map<string, RecipientNotification>();
      for (const n of existing) {
        map.set(n.notificationId, n);
      }
      for (const n of notifications) {
        map.set(n.notificationId, n);
      }
      localStorage.setItem('sih_notifications_v1', JSON.stringify(Array.from(map.values())));
    }
  }

  public async getNotification(notificationId: string): Promise<RecipientNotification | null> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve, reject) => {
        try {
          const tx = this.db!.transaction(STORES.NOTIFICATIONS, 'readonly');
          const store = tx.objectStore(STORES.NOTIFICATIONS);
          const req = store.get(notificationId);
          req.onsuccess = () => resolve(req.result || null);
          req.onerror = () => reject(req.error || new Error(`Failed to get notification ${notificationId}`));
        } catch (err) {
          reject(err);
        }
      });
    } else {
      const all = await this.getNotifications();
      return all.find((n) => n.notificationId === notificationId) || null;
    }
  }

  public async getNotifications(): Promise<RecipientNotification[]> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve, reject) => {
        try {
          const tx = this.db!.transaction(STORES.NOTIFICATIONS, 'readonly');
          const store = tx.objectStore(STORES.NOTIFICATIONS);
          const req = store.getAll();
          req.onsuccess = () => {
            const list = (req.result || []) as RecipientNotification[];
            resolve(list.sort((a, b) => b.timestamp - a.timestamp));
          };
          req.onerror = () => reject(req.error || new Error('Failed to retrieve notifications'));
        } catch (err) {
          reject(err);
        }
      });
    } else {
      const raw = localStorage.getItem('sih_notifications_v1');
      const list = raw ? (JSON.parse(raw) as RecipientNotification[]) : [];
      return list.sort((a, b) => b.timestamp - a.timestamp);
    }
  }

  public async getNotificationsByRecipient(recipientId: string): Promise<RecipientNotification[]> {
    await this.isReady();
    if (this.db) {
      return new Promise((resolve, reject) => {
        try {
          const tx = this.db!.transaction(STORES.NOTIFICATIONS, 'readonly');
          const store = tx.objectStore(STORES.NOTIFICATIONS);
          const index = store.index('recipientId');
          const req = index.getAll(recipientId);
          req.onsuccess = () => {
            const list = (req.result || []) as RecipientNotification[];
            resolve(list.sort((a, b) => b.timestamp - a.timestamp));
          };
          req.onerror = () => reject(req.error || new Error(`Failed to get notifications for recipient ${recipientId}`));
        } catch (err) {
          reject(err);
        }
      });
    } else {
      const all = await this.getNotifications();
      return all.filter((n) => n.recipientId === recipientId).sort((a, b) => b.timestamp - a.timestamp);
    }
  }

  public async markNotificationAsRead(notificationId: string, recipientId?: string): Promise<RecipientNotification | null> {
    const existing = await this.getNotification(notificationId);
    if (!existing) {
      return null;
    }
    // Enforce recipient isolation if caller provides recipientId
    if (recipientId && existing.recipientId !== recipientId) {
      throw new Error(`Unauthorized: notification does not belong to recipient ${recipientId}`);
    }
    const updated: RecipientNotification = {
      ...existing,
      read: true,
      readAt: Date.now(),
    };
    await this.saveNotification(updated);
    return updated;
  }

  public async markAllNotificationsAsRead(recipientId: string): Promise<void> {
    const notifications = await this.getNotificationsByRecipient(recipientId);
    const unread = notifications.filter((n) => !n.read);
    if (unread.length === 0) return;
    const now = Date.now();
    const updated = unread.map((n) => ({
      ...n,
      read: true,
      readAt: now,
    }));
    await this.saveNotifications(updated);
  }

  public async clearNotifications(): Promise<void> {
    await this.isReady();
    if (this.db) {
      await this.executeTxWrite(STORES.NOTIFICATIONS, (store) => store.clear());
    }
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('sih_notifications_v1');
    }
  }

  // --- HARD RESET ---
  public async clearAll(): Promise<void> {
    await this.isReady();
    if (this.db) {
      const tx = this.db.transaction(
        [
          STORES.BLOCKS,
          STORES.RECIPIENTS,
          STORES.PACKAGES,
          STORES.KEYSTORES,
          STORES.AUDIT_LOGS,
          STORES.ASSIGNMENTS,
          STORES.NOTIFICATIONS,
        ],
        'readwrite'
      );
      tx.objectStore(STORES.BLOCKS).clear();
      tx.objectStore(STORES.RECIPIENTS).clear();
      tx.objectStore(STORES.PACKAGES).clear();
      tx.objectStore(STORES.KEYSTORES).clear();
      tx.objectStore(STORES.AUDIT_LOGS).clear();
      tx.objectStore(STORES.ASSIGNMENTS).clear();
      tx.objectStore(STORES.NOTIFICATIONS).clear();
    }
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('sih_dlt_blocks');
      localStorage.removeItem('sih_packages');
      localStorage.removeItem('sih_recipients');
      localStorage.removeItem('sih_forensic_cases');
      localStorage.removeItem('sih_attribution_certificates');
      localStorage.removeItem('sih_security_incidents_v1');
      localStorage.removeItem('sih_forensic_dossiers_v1');
      localStorage.removeItem('sih_package_audit_logs');
      localStorage.removeItem('sih_assignments_v1');
      localStorage.removeItem('sih_notifications_v1');
    }
  }
}

export const airGappedStorage = new AirGappedStorage();
