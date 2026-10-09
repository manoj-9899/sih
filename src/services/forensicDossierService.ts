/**
 * Forensic Dossier Service.
 * 
 * Generates comprehensive, court-ready investigation reports from Security Incidents.
 * Features:
 * 1. Deterministic canonical JSON generation (RFC 8785) with dossierDigestSha256 computed
 *    over the content with the digest field excluded.
 * 2. Independent live evidence reference validation against authentic append-only audit records.
 * 3. Separate reporting of Issuance-Time vs Live Verification states.
 * 4. Explicit PDF generation with pdf-lib and clear verification boundary statements.
 * 5. Strict legal language: never claims cryptographic watermarks or signatures alone prove
 *    real-world intent or direct physical agency.
 * 6. Audit logging of dossier generation and verification without recursive loops.
 */

import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';
import {
  ForensicDossier,
  DossierEvidenceRecord,
  DossierProvenanceContext,
  DossierVerificationResult,
  IssuanceVerificationSnapshot,
} from '../types/dossier';
import { SecurityIncident } from '../types/incident';
import { auditService } from './auditService';
import { airGappedStorage } from '../storage/airGappedStorage';
import { canonicalizeJson, sha256Hex, bytesToHex } from '../crypto/pqc';

export const DOSSIER_INTENT_DISCLAIMER =
  'NOTICE OF CRYPTOGRAPHIC LIMITATION: Cryptographic signatures, key encapsulation records, and forensic watermarks establish mathematical non-repudiation of an associated decryption session. They do not prove real-world human intent, physical agency, or deliberate collusion in unauthorized disclosure.';

export const DOSSIER_SIMULATED_INFRASTRUCTURE_NOTICE =
  'WORKSTATION ENCLAVE NOTICE: This dossier was compiled on an air-gapped cryptographic workstation. Validator consensus attestations and local storage records reflect host-local enclave state.';

export class ForensicDossierService {
  /**
   * Generates a unique Dossier ID with year and entropy.
   */
  public static generateDossierId(): string {
    const entropy = crypto.getRandomValues(new Uint8Array(4));
    const hex = bytesToHex(entropy).toUpperCase();
    return `DOSSIER-${new Date().getFullYear()}-${hex.slice(0, 4)}-${hex.slice(4)}`;
  }

  /**
   * Generates a structured investigation dossier from a Security Incident.
   */
  public static async generateDossier(
    incident: SecurityIncident,
    investigator: { id: string; name: string; role: string }
  ): Promise<ForensicDossier> {
    const allAuditEvents = await auditService.getAllEvents();
    const liveAuditChainCheck = await auditService.verifyAuditChain();

    // 1. Reconstruct evidence timeline from authentic audit records
    const evidenceTimeline: DossierEvidenceRecord[] = [];
    const missingEvidence: string[] = [];

    for (const evtId of incident.evidenceEventIds) {
      const match = allAuditEvents.find((e) => e.eventId === evtId);
      if (match) {
        evidenceTimeline.push({
          eventId: match.eventId,
          timestampEpochMs: match.timestampEpochMs,
          timestampIso: match.timestamp,
          eventType: match.eventType,
          category: match.category,
          severity: match.severity,
          outcome: match.outcome,
          actor: match.actor,
          resource: match.resource,
          summary: match.description,
          eventHashSha256: match.eventHash || '',
          dltAnchored: !!match.dltAnchored,
          dltBlockHeight: match.dltBlockHeight || match.blockIndex,
          verifiedInAuditChain: liveAuditChainCheck.valid,
        });
      } else {
        missingEvidence.push(evtId);
      }
    }

    // Sort evidence timeline chronologically
    evidenceTimeline.sort((a, b) => a.timestampEpochMs - b.timestampEpochMs);

    // 2. Issuance-Time Cryptographic Verification Snapshot
    const issuanceVerification: IssuanceVerificationSnapshot = {
      auditChainValid: liveAuditChainCheck.valid,
      auditChainEventsChecked: liveAuditChainCheck.eventsChecked,
      auditChainHeadDigest: liveAuditChainCheck.latestEventHash || 'GENESIS',
      evidenceDigestConsistency: incident.evidenceDigest,
      allEvidenceEventsExisted: missingEvidence.length === 0,
      timestampEpochMs: Date.now(),
    };

    // 3. Correlated Provenance Context (Attribution Certificates & DLT)
    let forensicProvenance: DossierProvenanceContext | undefined;
    const certs = await airGappedStorage.getAttributionCertificates();
    const matchedCert = certs.find(
      (c: any) =>
        c.document?.documentId === incident.affectedDocumentId ||
        c.attributionTarget?.recipientId === incident.affectedRecipientId
    );

    if (matchedCert) {
      forensicProvenance = {
        associatedCertificateId: matchedCert.certificateId,
        certificateAttributionStatement: matchedCert.attributionStatement,
        watermarkCommitmentHex: matchedCert.cryptographicProof?.watermarkCommitment,
        watermarkId: matchedCert.document?.watermarkId,
        dltTransactionId: matchedCert.cryptographicProof?.dltTransactionId,
        dltBlockHeight: matchedCert.cryptographicProof?.ledgerBlockHeight,
        blockHash: matchedCert.cryptographicProof?.blockHash,
        merkleRoot: matchedCert.cryptographicProof?.merkleRoot,
        validatorQuorumCount: matchedCert.cryptographicProof?.validatorQuorum?.validators?.length,
        merkleProofValid: matchedCert.cryptographicProof?.merkleProofValid,
      };
    } else if (incident.affectedBlockIndex) {
      forensicProvenance = {
        dltBlockHeight: incident.affectedBlockIndex,
      };
    }

    // 4. Response History Compilation
    const responseHistory = {
      statusTransitions: [
        {
          timestamp: incident.firstObservedAt,
          from: 'NONE',
          to: 'OPEN',
          author: 'SYSTEM (SecurityIncidentEngine)',
        },
      ],
      containmentActions: incident.responseActions.map((act) => ({
        actionType: act.actionType,
        executedAt: act.executedAt,
        actor: `${act.actorDisplayName || act.actorId}`,
        details: act.details,
        outcome: act.outcome,
      })),
      investigatorNotes: incident.investigatorNotes.map((note) => ({
        timestamp: note.timestamp,
        author: note.authorDisplayName,
        text: note.text,
      })),
      resolution: incident.resolution,
    };

    const dossierId = this.generateDossierId();
    const generatedAtEpochMs = Date.now();

    // 5. Build Base Dossier without digest
    const dossierBase = {
      dossierId,
      sourceIncidentId: incident.incidentId,
      generatedAtEpochMs,
      generatedAtIso: new Date(generatedAtEpochMs).toISOString(),
      generatedBy: investigator,
      incidentSummary: {
        incidentId: incident.incidentId,
        incidentType: incident.incidentType,
        severity: incident.severity,
        confidence: incident.confidence,
        status: incident.status,
        ruleId: incident.ruleId,
        detectionRuleName: incident.detectionRuleName,
        firstObservedAtIso: new Date(incident.firstObservedAt).toISOString(),
        lastObservedAtIso: new Date(incident.lastObservedAt).toISOString(),
        description: incident.description,
      },
      affectedEntities: {
        recipientId: incident.affectedRecipientId,
        recipientName: incident.affectedRecipientName,
        documentId: incident.affectedDocumentId,
        packageId: incident.affectedPackageId,
        blockIndex: incident.affectedBlockIndex,
      },
      evidenceTimeline,
      issuanceVerification,
      forensicProvenance,
      responseHistory,
      limitations: {
        missingEvidence,
        simulatedInfrastructureNotice: DOSSIER_SIMULATED_INFRASTRUCTURE_NOTICE,
        intentDisclaimer: DOSSIER_INTENT_DISCLAIMER,
      },
    };

    // 6. Compute Canonical SHA-256 Digest over content with digest field excluded
    const canonicalContent = canonicalizeJson(dossierBase);
    const dossierDigestSha256 = await sha256Hex(canonicalContent);

    const dossier: ForensicDossier = {
      ...dossierBase,
      dossierDigestSha256,
    };

    // 7. Persist Dossier
    await airGappedStorage.saveForensicDossier(dossier);

    // 8. Record audit log of dossier generation
    await auditService.record({
      eventType: 'DOSSIER_GENERATED',
      severity: 'NOTICE',
      category: 'SECURITY',
      actor: { type: 'USER', id: investigator.id, displayName: investigator.name },
      resource: { type: 'INVESTIGATION', id: dossierId },
      action: 'GENERATE_DOSSIER',
      outcome: 'SUCCESS',
      description: `Generated Forensic Dossier ${dossierId} for incident ${incident.incidentId}. Digest: ${dossierDigestSha256.slice(0, 16)}...`,
      caseId: incident.incidentId,
      recipientId: incident.affectedRecipientId,
      documentId: incident.affectedDocumentId,
      packageId: incident.affectedPackageId,
    }).catch(() => {});

    return dossier;
  }

  /**
   * Cryptographically verifies an existing Forensic Dossier.
   * Compares the canonical digest (with digest field excluded) and validates each evidence
   * reference directly against the authentic audit store and live chain state.
   */
  public static async verifyDossier(
    input: ForensicDossier | string
  ): Promise<DossierVerificationResult> {
    const checks: DossierVerificationResult['checks'] = [];
    let dossier: ForensicDossier;

    try {
      dossier = typeof input === 'string' ? JSON.parse(input) : input;
    } catch {
      return {
        valid: false,
        tamperDetected: true,
        tamperReason: 'Malformed dossier JSON.',
        calculatedDigestSha256: '',
        storedDigestSha256: '',
        digestMatch: false,
        pdfVerificationNote: 'Cannot verify PDF boundary: malformed JSON.',
        issuanceVerification: {
          auditChainValid: false,
          auditChainEventsChecked: 0,
          auditChainHeadDigest: '',
          evidenceDigestConsistency: '',
          allEvidenceEventsExisted: false,
          timestampEpochMs: 0,
        },
        currentLiveVerification: {
          auditChainValid: false,
          auditChainEventsChecked: 0,
          auditChainHeadDigest: '',
          allEvidenceEventsMatchLiveStore: false,
          missingEventIds: [],
          mismatchedEventIds: [],
        },
        checks: [{ check: 'Format Verification', passed: false, message: 'Invalid JSON payload' }],
      };
    }

    const { dossierDigestSha256, pdfDigestSha256, ...withoutDigest } = dossier;

    // Check 1: Canonical Content Digest Verification
    const calculatedDigestSha256 = await sha256Hex(canonicalizeJson(withoutDigest));
    const digestMatch = calculatedDigestSha256.toLowerCase() === (dossierDigestSha256 || '').toLowerCase();
    checks.push({
      check: 'Canonical Content Digest Integrity',
      passed: digestMatch,
      message: digestMatch
        ? `Canonical SHA-256 matches stored digest (${calculatedDigestSha256.slice(0, 16)}...).`
        : `Digest mismatch: expected "${dossierDigestSha256?.slice(0, 16)}...", computed "${calculatedDigestSha256.slice(0, 16)}...". Content altered.`,
    });

    // Check 2: Independent Live Audit Chain Verification
    const liveChain = await auditService.verifyAuditChain();
    checks.push({
      check: 'Underlying Audit Hash Chain Integrity',
      passed: liveChain.valid,
      message: liveChain.valid
        ? `Audit hash chain intact (${liveChain.eventsChecked} events verified).`
        : `Audit hash chain broken: ${liveChain.reason || 'Tampering detected'}.`,
    });

    // Check 3: Evidence Reference Cross-Validation against Authentic Append-Only Store
    const allLiveEvents = await auditService.getAllEvents();
    const missingEventIds: string[] = [];
    const mismatchedEventIds: string[] = [];

    for (const claimedEvt of dossier.evidenceTimeline || []) {
      const match = allLiveEvents.find((e) => e.eventId === claimedEvt.eventId);
      if (!match) {
        missingEventIds.push(claimedEvt.eventId);
      } else if (match.eventHash && claimedEvt.eventHashSha256 && match.eventHash !== claimedEvt.eventHashSha256) {
        mismatchedEventIds.push(claimedEvt.eventId);
      }
    }

    const evidenceValid = missingEventIds.length === 0 && mismatchedEventIds.length === 0;
    checks.push({
      check: 'Authentic Evidence Store Cross-Validation',
      passed: evidenceValid,
      message: evidenceValid
        ? `All ${dossier.evidenceTimeline?.length || 0} evidence references confirmed in live audit store.`
        : `Evidence invalid: ${missingEventIds.length} missing, ${mismatchedEventIds.length} hash mismatched.`,
    });

    // Check 4: Mandatory Legal Disclaimer Presence
    const disclaimerPresent = !!(
      dossier.limitations?.intentDisclaimer &&
      dossier.limitations.intentDisclaimer.includes('mathematical non-repudiation')
    );
    checks.push({
      check: 'Mandatory Non-Repudiation Limitation Disclaimer',
      passed: disclaimerPresent,
      message: disclaimerPresent
        ? 'Legal non-repudiation boundary disclosure intact.'
        : 'Missing required legal intent disclaimer.',
    });

    const isFullyValid = digestMatch && liveChain.valid && evidenceValid && disclaimerPresent;

    // Record verification audit event
    await auditService.record({
      eventType: isFullyValid ? 'DOSSIER_VERIFIED' : 'DOSSIER_VERIFICATION_FAILED',
      severity: isFullyValid ? 'INFO' : 'ERROR',
      category: 'SECURITY',
      actor: { type: 'SYSTEM', id: 'DOSSIER_VERIFIER' },
      resource: { type: 'INVESTIGATION', id: dossier.dossierId },
      action: 'VERIFY_DOSSIER',
      outcome: isFullyValid ? 'SUCCESS' : 'FAILURE',
      description: `Cryptographic audit of dossier ${dossier.dossierId}: ${isFullyValid ? 'VERIFIED' : 'FAILED'} (Digest match: ${digestMatch}, Chain: ${liveChain.valid}).`,
      caseId: dossier.sourceIncidentId,
    }).catch(() => {});

    return {
      valid: isFullyValid,
      tamperDetected: !digestMatch || !evidenceValid,
      tamperReason: !digestMatch
        ? 'Dossier content digest mismatch.'
        : !evidenceValid
        ? 'Evidence references do not match authentic live audit store.'
        : undefined,
      calculatedDigestSha256,
      storedDigestSha256: dossierDigestSha256 || '',
      digestMatch,
      pdfDigestSha256: dossier.pdfDigestSha256,
      pdfVerificationNote:
        'The canonical JSON digest covers machine-readable structured claims. The PDF is verified via its explicit SHA-256 binary hash or visual watermark seals.',
      issuanceVerification: dossier.issuanceVerification,
      currentLiveVerification: {
        auditChainValid: liveChain.valid,
        auditChainEventsChecked: liveChain.eventsChecked,
        auditChainHeadDigest: liveChain.latestEventHash || '',
        allEvidenceEventsMatchLiveStore: evidenceValid,
        missingEventIds,
        mismatchedEventIds,
      },
      checks,
    };
  }

  /**
   * Generates a court-ready, high-fidelity PDF investigation dossier using pdf-lib.
   */
  public static async generateDossierPdf(dossier: ForensicDossier): Promise<Uint8Array> {
    const pdfDoc = await PDFDocument.create();
    const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
    const fontMono = await pdfDoc.embedFont(StandardFonts.Courier);

    const navy = rgb(0.08, 0.16, 0.28);
    const slateDark = rgb(0.18, 0.22, 0.28);
    const textMuted = rgb(0.42, 0.48, 0.55);
    const emerald = rgb(0.05, 0.6, 0.35);
    const amber = rgb(0.85, 0.45, 0.1);
    const rose = rgb(0.85, 0.2, 0.2);

    const page = pdfDoc.addPage([595.28, 841.89]); // A4
    const { width, height } = page.getSize();

    // 1. Header Banner
    page.drawRectangle({
      x: 30,
      y: height - 100,
      width: width - 60,
      height: 70,
      color: navy,
    });

    page.drawRectangle({
      x: 30,
      y: height - 103,
      width: width - 60,
      height: 3,
      color: dossier.incidentSummary.severity === 'CRITICAL' ? rose : emerald,
    });

    page.drawText('OFFICIAL INCIDENT INVESTIGATION DOSSIER', {
      x: 50,
      y: height - 60,
      size: 15,
      font: fontBold,
      color: rgb(1, 1, 1),
    });

    page.drawText('POST-QUANTUM CRYPTOGRAPHIC EVIDENCE & FORENSIC ATTRIBUTION REPORT', {
      x: 50,
      y: height - 76,
      size: 7.5,
      font: fontRegular,
      color: rgb(0.8, 0.88, 0.95),
    });

    page.drawText(`STATUS: ${dossier.incidentSummary.status} | SEVERITY: ${dossier.incidentSummary.severity} | CONFIDENCE: ${dossier.incidentSummary.confidence}`, {
      x: 50,
      y: height - 90,
      size: 7,
      font: fontMono,
      color: rgb(0.5, 0.85, 0.6),
    });

    // 2. Metadata Bar
    let y = height - 125;
    page.drawText(`DOSSIER ID: ${dossier.dossierId}`, { x: 35, y, size: 8, font: fontMono, color: navy });
    page.drawText(`INCIDENT ID: ${dossier.sourceIncidentId}`, { x: 230, y, size: 8, font: fontMono, color: navy });
    page.drawText(`COMPILED: ${new Date(dossier.generatedAtEpochMs).toUTCString()}`, { x: 400, y, size: 7.5, font: fontMono, color: textMuted });

    y -= 15;
    page.drawLine({ start: { x: 35, y }, end: { x: width - 35, y }, thickness: 0.5, color: rgb(0.85, 0.88, 0.92) });

    // 3. Section I: Executive Threat Summary
    y -= 20;
    page.drawText('I. EXECUTIVE THREAT ASSESSMENT', { x: 35, y, size: 10, font: fontBold, color: navy });
    y -= 15;
    page.drawText(`Detection Rule: ${dossier.incidentSummary.detectionRuleName} (${dossier.incidentSummary.ruleId})`, { x: 40, y, size: 8.5, font: fontBold, color: slateDark });
    y -= 13;
    page.drawText(`Incident Type: ${dossier.incidentSummary.incidentType}`, { x: 40, y, size: 8, font: fontMono, color: textMuted });
    y -= 13;

    // Wrap description
    const desc = dossier.incidentSummary.description;
    const maxChars = 95;
    for (let i = 0; i < desc.length; i += maxChars) {
      page.drawText(desc.slice(i, i + maxChars), { x: 40, y, size: 8, font: fontRegular, color: slateDark });
      y -= 11;
    }

    // 4. Section II: Correlated Entities
    y -= 10;
    page.drawText('II. CORRELATED TARGET ENTITIES', { x: 35, y, size: 10, font: fontBold, color: navy });
    y -= 15;
    if (dossier.affectedEntities.recipientId) {
      page.drawText(`Target Recipient: ${dossier.affectedEntities.recipientName || ''} (${dossier.affectedEntities.recipientId})`, { x: 40, y, size: 8, font: fontMono, color: slateDark });
      y -= 12;
    }
    if (dossier.affectedEntities.packageId) {
      page.drawText(`Container / Package: ${dossier.affectedEntities.packageId}`, { x: 40, y, size: 8, font: fontMono, color: slateDark });
      y -= 12;
    }
    if (dossier.affectedEntities.documentId) {
      page.drawText(`Classified Document: ${dossier.affectedEntities.documentId}`, { x: 40, y, size: 8, font: fontMono, color: slateDark });
      y -= 12;
    }
    if (dossier.affectedEntities.blockIndex) {
      page.drawText(`DLT Provenance Block: Height #${dossier.affectedEntities.blockIndex}`, { x: 40, y, size: 8, font: fontMono, color: slateDark });
      y -= 12;
    }

    // 5. Section III: Cryptographic Evidence Chain Table
    y -= 10;
    page.drawText('III. CRYPTOGRAPHIC EVIDENCE CHAIN (AUDIT TRAIL)', { x: 35, y, size: 10, font: fontBold, color: navy });
    y -= 15;

    // Table Header
    page.drawRectangle({ x: 35, y: y - 3, width: width - 70, height: 14, color: rgb(0.93, 0.95, 0.98) });
    page.drawText('EVENT ID', { x: 40, y: y + 2, size: 7, font: fontBold, color: navy });
    page.drawText('TIMESTAMP (UTC)', { x: 130, y: y + 2, size: 7, font: fontBold, color: navy });
    page.drawText('TYPE / ACTION', { x: 240, y: y + 2, size: 7, font: fontBold, color: navy });
    page.drawText('OUTCOME', { x: 400, y: y + 2, size: 7, font: fontBold, color: navy });
    page.drawText('DLT ANCHOR', { x: 470, y: y + 2, size: 7, font: fontBold, color: navy });
    y -= 16;

    // Evidence rows (capped to first 8 for single page readability)
    for (const evt of dossier.evidenceTimeline.slice(0, 8)) {
      page.drawText(evt.eventId, { x: 40, y, size: 6.5, font: fontMono, color: slateDark });
      page.drawText(new Date(evt.timestampEpochMs).toUTCString().slice(5, 22), { x: 130, y, size: 6.5, font: fontMono, color: textMuted });
      page.drawText(evt.eventType.slice(0, 26), { x: 240, y, size: 6.5, font: fontMono, color: slateDark });
      page.drawText(evt.outcome, { x: 400, y, size: 6.5, font: fontBold, color: evt.outcome === 'SUCCESS' ? emerald : rose });
      page.drawText(evt.dltAnchored ? `Block #${evt.dltBlockHeight || 1}` : 'Local', { x: 470, y, size: 6.5, font: fontMono, color: textMuted });
      y -= 12;
    }

    // 6. Section IV: Issuance Verification State
    y -= 10;
    page.drawText('IV. CRYPTOGRAPHIC VERIFICATION AT ISSUANCE', { x: 35, y, size: 10, font: fontBold, color: navy });
    y -= 14;
    page.drawText(`Audit Chain Status: ${dossier.issuanceVerification.auditChainValid ? 'VERIFIED INTACT' : 'TAMPERING DETECTED'} (${dossier.issuanceVerification.auditChainEventsChecked} events checked)`, { x: 40, y, size: 8, font: fontMono, color: dossier.issuanceVerification.auditChainValid ? emerald : rose });
    y -= 12;
    page.drawText(`Audit Chain Head: ${dossier.issuanceVerification.auditChainHeadDigest.slice(0, 36)}...`, { x: 40, y, size: 7.5, font: fontMono, color: textMuted });
    y -= 12;
    page.drawText(`Dossier Content Digest (SHA-256): ${dossier.dossierDigestSha256}`, { x: 40, y, size: 7, font: fontMono, color: navy });
    y -= 15;

    // 7. Mandatory Legal Disclaimers (Boxed Footer)
    page.drawRectangle({
      x: 35,
      y: 40,
      width: width - 70,
      height: 65,
      color: rgb(0.96, 0.97, 0.98),
      borderColor: rgb(0.85, 0.88, 0.92),
      borderWidth: 1,
    });

    page.drawText('MANDATORY LEGAL LIMITATION & WORKSTATION DISCLOSURE', {
      x: 45,
      y: 92,
      size: 7,
      font: fontBold,
      color: navy,
    });

    page.drawText(DOSSIER_INTENT_DISCLAIMER.slice(0, 115), { x: 45, y: 80, size: 6.5, font: fontRegular, color: textMuted });
    page.drawText(DOSSIER_INTENT_DISCLAIMER.slice(115), { x: 45, y: 70, size: 6.5, font: fontRegular, color: textMuted });
    page.drawText(DOSSIER_SIMULATED_INFRASTRUCTURE_NOTICE, { x: 45, y: 56, size: 6.5, font: fontMono, color: textMuted });
    page.drawText(`Certified by: ${dossier.generatedBy.name} (${dossier.generatedBy.role})`, { x: 45, y: 46, size: 6.5, font: fontBold, color: navy });

    return await pdfDoc.save();
  }
}
