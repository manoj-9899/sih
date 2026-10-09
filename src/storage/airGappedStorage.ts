/**
 * Air-Gapped Persistent Storage Adapter using IndexedDB with fallback to localStorage.
 * Enables DLT blockchain state, recipient keystores, and encrypted packages
 * to survive browser refreshes and system reboots in an isolated offline environment.
 */

import { ForensicCaseRecord } from '../types';

const DB_NAME = 'sih26237_airgap_store_v1';
const DB_VERSION = 1;
const STORES = {
  BLOCKS: 'blocks',
  RECIPIENTS: 'recipients',
  PACKAGES: 'packages',
  KEYSTORES: 'keystores',
  AUDIT_LOGS: 'audit_logs',
};

class AirGappedStorage {
  private db: IDBDatabase | null = null;
  private isReadyPromise: Promise<boolean>;

  constructor() {
    this.isReadyPromise = this.initDB();
  }

  private async initDB(): Promise<boolean> {
    if (typeof window === 'undefined' || !window.indexedDB) {
      console.warn('[AirGappedStorage] IndexedDB unavailable, using memory/localStorage fallback.');
      return false;
    }

    return new Promise((resolve) => {
      try {
        const request = window.indexedDB.open(DB_NAME, DB_VERSION);

        request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
          const db = (event.target as IDBOpenDBRequest).result;
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
        };

        request.onsuccess = () => {
          this.db = request.result;
          resolve(true);
        };

        request.onerror = () => {
          console.warn('[AirGappedStorage] IndexedDB open error, falling back.');
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

  // --- BLOCKS ---
  public async saveBlocks(blocks: any[]): Promise<void> {
    await this.isReady();
    if (this.db) {
      const tx = this.db.transaction(STORES.BLOCKS, 'readwrite');
      const store = tx.objectStore(STORES.BLOCKS);
      for (const b of blocks) {
        store.put(b);
      }
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
      const tx = this.db.transaction(STORES.BLOCKS, 'readwrite');
      tx.objectStore(STORES.BLOCKS).clear();
    }
    localStorage.removeItem('sih_dlt_blocks');
  }

  // --- PACKAGES ---
  public async savePackage(pkg: any): Promise<void> {
    await this.isReady();
    if (this.db) {
      const tx = this.db.transaction(STORES.PACKAGES, 'readwrite');
      tx.objectStore(STORES.PACKAGES).put(pkg);
    } else {
      const existing = await this.getPackages() || [];
      const updated = existing.filter(p => p.packageId !== pkg.packageId).concat(pkg);
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
      const tx = this.db.transaction(STORES.PACKAGES, 'readwrite');
      tx.objectStore(STORES.PACKAGES).clear();
    }
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('sih_packages');
    }
  }

  // --- KEYSTORES ---
  public async saveKeystore(keystore: { keyId: string; [key: string]: any }): Promise<void> {
    await this.isReady();
    if (this.db) {
      const tx = this.db.transaction(STORES.KEYSTORES, 'readwrite');
      const store = tx.objectStore(STORES.KEYSTORES);
      store.put(keystore);
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
      const tx = this.db.transaction(STORES.RECIPIENTS, 'readwrite');
      const store = tx.objectStore(STORES.RECIPIENTS);
      for (const r of recipients) {
        store.put(r);
      }
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
      // Keep most recent 50 cases
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
        const tx = this.db.transaction(STORES.AUDIT_LOGS, 'readwrite');
        tx.objectStore(STORES.AUDIT_LOGS).add(event);
      } catch (err) {
        console.warn('[AirGappedStorage] Failed to save audit log to IDB:', err);
      }
    }
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const item = localStorage.getItem('sih_package_audit_logs');
        const list = item ? JSON.parse(item) : [];
        // Append in chronological order (or replace if existing by eventId)
        const filtered = list.filter((e: any) => e.eventId !== event.eventId);
        filtered.push(event);
        // Keep up to 500 events locally
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
        const tx = this.db.transaction(STORES.AUDIT_LOGS, 'readwrite');
        tx.objectStore(STORES.AUDIT_LOGS).clear();
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

  // --- HARD RESET ---
  public async clearAll(): Promise<void> {
    await this.isReady();
    if (this.db) {
      const tx = this.db.transaction([STORES.BLOCKS, STORES.RECIPIENTS, STORES.PACKAGES, STORES.KEYSTORES, STORES.AUDIT_LOGS], 'readwrite');
      tx.objectStore(STORES.BLOCKS).clear();
      tx.objectStore(STORES.RECIPIENTS).clear();
      tx.objectStore(STORES.PACKAGES).clear();
      tx.objectStore(STORES.KEYSTORES).clear();
      tx.objectStore(STORES.AUDIT_LOGS).clear();
    }
    localStorage.removeItem('sih_dlt_blocks');
    localStorage.removeItem('sih_packages');
    localStorage.removeItem('sih_recipients');
    localStorage.removeItem('sih_forensic_cases');
    localStorage.removeItem('sih_security_incidents_v1');
    localStorage.removeItem('sih_forensic_dossiers_v1');
  }
}

export const airGappedStorage = new AirGappedStorage();
