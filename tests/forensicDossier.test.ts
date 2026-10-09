import './setup';
import { test, describe, before, beforeEach } from 'node:test';
import assert from 'node:assert';
import { ForensicDossierService, DOSSIER_INTENT_DISCLAIMER } from '../src/services/forensicDossierService';
import { securityIncidentEngine } from '../src/services/incidentEngine';
import { auditService } from '../src/services/auditService';
import { airGappedStorage } from '../src/storage/airGappedStorage';
import { airGappedLedger } from '../src/ledger/dlt';
import { canonicalizeJson, sha256Hex } from '../src/crypto/pqc';
import { SecurityIncident } from '../src/types/incident';

describe('INCIDENT REPORTING & FORENSIC DOSSIER SUITE (DOS-01 to DOS-09)', () => {
  let sampleIncident: SecurityIncident;

  before(async () => {
    await airGappedLedger.initGenesis();
  });

  beforeEach(async () => {
    await securityIncidentEngine.clearAll();
    await auditService.clearAll();
    await airGappedStorage.clearForensicDossiers();

    // Generate authentic audit records for an incident
    const e1 = await auditService.record({
      eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      severity: 'WARNING',
      category: 'AUTHORIZATION',
      actor: { type: 'USER', id: 'REC-INTRUDER-99', displayName: 'Agent Intruder' },
      resource: { type: 'PACKAGE', id: 'PKG-TOP-SECRET' },
      action: 'DECRYPT_DOCUMENT',
      outcome: 'DENIED',
      description: 'First unauthorized access denial',
      recipientId: 'REC-INTRUDER-99',
      packageId: 'PKG-TOP-SECRET',
      documentId: 'DOC-CONFIDENTIAL-01',
    });

    const e2 = await auditService.record({
      eventType: 'UNAUTHORIZED_DECRYPTION_ATTEMPT',
      severity: 'WARNING',
      category: 'SECURITY',
      actor: { type: 'USER', id: 'REC-INTRUDER-99', displayName: 'Agent Intruder' },
      resource: { type: 'PACKAGE', id: 'PKG-TOP-SECRET' },
      action: 'DECRYPT_DOCUMENT',
      outcome: 'DENIED',
      description: 'Second unauthorized access denial',
      recipientId: 'REC-INTRUDER-99',
      packageId: 'PKG-TOP-SECRET',
      documentId: 'DOC-CONFIDENTIAL-01',
    });

    // Synthesize incident via engine
    const incidents = await securityIncidentEngine.evaluateAuditStream();
    assert.strictEqual(incidents.length, 1);
    sampleIncident = incidents[0];
  });

  test('DOS-01: Valid Dossier Generation with all mandatory sections and canonical digest', async () => {
    const investigator = {
      id: 'INV-SMITH',
      name: 'Special Agent Smith',
      role: 'Forensic Lead',
    };

    const dossier = await ForensicDossierService.generateDossier(sampleIncident, investigator);

    assert.ok(dossier.dossierId.startsWith('DOSSIER-'));
    assert.strictEqual(dossier.sourceIncidentId, sampleIncident.incidentId);
    assert.strictEqual(dossier.generatedBy.id, 'INV-SMITH');
    assert.strictEqual(dossier.evidenceTimeline.length, 2);
    assert.ok(dossier.dossierDigestSha256 && dossier.dossierDigestSha256.length === 64);
    assert.strictEqual(dossier.limitations.intentDisclaimer, DOSSIER_INTENT_DISCLAIMER);

    // Verify issuance verification snapshot
    assert.strictEqual(dossier.issuanceVerification.auditChainValid, true);
    assert.strictEqual(dossier.issuanceVerification.allEvidenceEventsExisted, true);
  });

  test('DOS-02: Deterministic Canonical Hashing excludes digest field', async () => {
    const dossier = await ForensicDossierService.generateDossier(sampleIncident, {
      id: 'INV-01',
      name: 'Auditor',
      role: 'Lead',
    });

    const { dossierDigestSha256, pdfDigestSha256, ...withoutDigest } = dossier;
    const computed = await sha256Hex(canonicalizeJson(withoutDigest));

    assert.strictEqual(computed, dossierDigestSha256, 'Digest must match canonical JSON with digest field excluded');
  });

  test('DOS-03: Tamper Detection — Altering summary or fields causes digest mismatch', async () => {
    const dossier = await ForensicDossierService.generateDossier(sampleIncident, {
      id: 'INV-01',
      name: 'Auditor',
      role: 'Lead',
    });

    // Tamper with severity
    const tampered = JSON.parse(JSON.stringify(dossier));
    tampered.incidentSummary.severity = 'LOW';

    const result = await ForensicDossierService.verifyDossier(tampered);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.tamperDetected, true);
    assert.strictEqual(result.digestMatch, false);
  });

  test('DOS-04: Fake Evidence Reference Detection — Nonexistent event IDs fail verification', async () => {
    const dossier = await ForensicDossierService.generateDossier(sampleIncident, {
      id: 'INV-01',
      name: 'Auditor',
      role: 'Lead',
    });

    // Tamper evidence timeline with forged event ID and recompute digest
    const tampered = JSON.parse(JSON.stringify(dossier));
    tampered.evidenceTimeline[0].eventId = 'EVT-FAKE-FORGED-999';
    const { dossierDigestSha256, ...withoutDigest } = tampered;
    tampered.dossierDigestSha256 = await sha256Hex(canonicalizeJson(withoutDigest));

    // Even though the digest matches the forged JSON, cross-referencing against authentic audit store must fail!
    const result = await ForensicDossierService.verifyDossier(tampered);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.currentLiveVerification.allEvidenceEventsMatchLiveStore, false);
    assert.ok(result.currentLiveVerification.missingEventIds.includes('EVT-FAKE-FORGED-999'));
  });

  test('DOS-05: Broken Audit Chain Invalidation', async () => {
    const dossier = await ForensicDossierService.generateDossier(sampleIncident, {
      id: 'INV-01',
      name: 'Auditor',
      role: 'Lead',
    });

    // Tamper with live audit store
    auditService.simulateAuditTamper(0, 'ALTERED_STORE_RECORD');

    const result = await ForensicDossierService.verifyDossier(dossier);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.currentLiveVerification.auditChainValid, false);
  });

  test('DOS-06: Court-Ready PDF Generation produces valid binary bytes', async () => {
    const dossier = await ForensicDossierService.generateDossier(sampleIncident, {
      id: 'INV-01',
      name: 'Auditor',
      role: 'Lead',
    });

    const pdfBytes = await ForensicDossierService.generateDossierPdf(dossier);
    assert.ok(pdfBytes instanceof Uint8Array);
    assert.ok(pdfBytes.length > 1000);

    // Verify PDF Magic Bytes (%PDF-)
    const magic = String.fromCharCode(...pdfBytes.slice(0, 5));
    assert.strictEqual(magic, '%PDF-');
  });

  test('DOS-07: Incomplete Provenance Handling — Dossier handles incidents without certificates cleanly', async () => {
    const dossier = await ForensicDossierService.generateDossier(sampleIncident, {
      id: 'INV-01',
      name: 'Auditor',
      role: 'Lead',
    });

    // Incident without certificate should have empty or undefined cert fields, not crash
    assert.strictEqual(dossier.forensicProvenance?.associatedCertificateId, undefined);
    assert.strictEqual(dossier.limitations.missingEvidence.length, 0);

    const verification = await ForensicDossierService.verifyDossier(dossier);
    assert.strictEqual(verification.valid, true);
  });

  test('DOS-08: Persistence & Retrieval via Air-Gapped Storage', async () => {
    const dossier = await ForensicDossierService.generateDossier(sampleIncident, {
      id: 'INV-01',
      name: 'Auditor',
      role: 'Lead',
    });

    const loaded = await airGappedStorage.getForensicDossier(dossier.dossierId);
    assert.ok(loaded);
    assert.strictEqual(loaded.dossierId, dossier.dossierId);
    assert.strictEqual(loaded.dossierDigestSha256, dossier.dossierDigestSha256);
  });

  test('DOS-09: Audit Emission — Generating and Verifying Dossier emits audit events without recursion', async () => {
    const eventsBefore = (await auditService.getAllEvents()).length;

    const dossier = await ForensicDossierService.generateDossier(sampleIncident, {
      id: 'INV-01',
      name: 'Auditor',
      role: 'Lead',
    });

    await ForensicDossierService.verifyDossier(dossier);

    const eventsAfter = await auditService.getAllEvents();
    assert.ok(eventsAfter.length >= eventsBefore + 2);

    const genEvt = eventsAfter.find((e) => e.eventType === 'DOSSIER_GENERATED');
    const verEvt = eventsAfter.find((e) => e.eventType === 'DOSSIER_VERIFIED');

    assert.ok(genEvt);
    assert.ok(verEvt);

    // Verify incident engine did not spawn new incidents
    const incidents = await securityIncidentEngine.getAllIncidents();
    assert.strictEqual(incidents.length, 1);
  });
});
