/**
 * Sample Classified Intelligence Documents and Recipient Data.
 * Pre-generates NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) key material
 * for authorized defense recipients.
 */

import { ClassifiedDocument, Recipient } from '../types';
import { generateRecipientPqcKeys, bytesToHex, hexToBytes } from '../crypto/pqc';
import { airGappedLedger } from '../ledger/dlt';
import { airGappedStorage } from '../storage/airGappedStorage';
import { createUnifiedEncryptedKeystore, sanitizeRecipientForPersistence, unlockKeystoreRecord } from '../crypto/keystore';
import { createMinimalValidPdf } from '../crypto/pdfUtils';

export const SAMPLE_DOCUMENTS: ClassifiedDocument[] = [
  {
    id: 'DOC-2026-CONF-991',
    title: 'Confidential Research Report: Critical Infrastructure Security Matrix',
    classification: 'TOP SECRET // SCI',
    caveats: 'RESTRICTED DISSEMINATION // SPECIAL ACCESS REQUIRED',
    originatingOffice: 'Directorate of Strategic Security Assessment',
    isPdf: true,
    mimeType: 'application/pdf',
    filename: 'Critical_Infrastructure_Security_Matrix.pdf',
    fileSizeBytes: 442,
    pdfBytes: createMinimalValidPdf('Critical Infrastructure Security Matrix - TOP SECRET // SCI'),
    summary:
      'Operational deployment blueprints, cryptographic migration timelines, and secure channel key-management protocols.',
    rawText: `================================================================================
TOP SECRET // SCI // RESTRICTED DISSEMINATION
DOCUMENT CONTROL NUMBER: TS-SCI-2026-CR-0091
ORIGINATING AUTHORITY: STRATEGIC SECURITY ASSESSMENT DIRECTORATE
DATE: 28 SEPTEMBER 2026

SUBJECT: STRATEGIC INFRASTRUCTURE TRANSITION & POST-QUANTUM KEY MATRIX

1. EXECUTIVE DIRECTIVE
Under National Security Technical Directive 14-B, the following operational matrix
governs all quantum-hardened communications arrays across primary infrastructure networks.
All personnel accessing this material are bound by statutory confidentiality obligations.

2. FREQUENCY & KEY ALLOCATION TABLE (OCTOBER 2026 CYCLE)
- Array Alpha-1 (Northern Hub): Primary Key Ring KEM-768 [Rotation: 30 Days]
- Array Bravo-3 (Southern Hub): Secondary Key Ring KEM-768 [Rotation: 30 Days]
- Array Charlie-7 (Central Hub): Redundant Key Ring KEM-768 [Rotation: 15 Days]

3. RESILIENCE DIRECTIVE
In the event of an unauthorized channel interception or network boundary anomaly,
system controllers shall initiate autonomous post-quantum encrypted fallback
utilizing the NIST ML-KEM-768 key encapsulation standard.

4. DISSEMINATION REGISTER
Authorized personnel: Chief Intelligence Analyst, Senior Logistics Director, Systems Architect.
All distribution packages are forensically watermarked at point of local decryption.
================================================================================`,
    visualPages: [],
    createdAt: 1790610000000,
  },
  {
    id: 'DOC-2026-QUANTUM-GRID-442',
    title: 'CRITICAL INFRASTRUCTURE: Post-Quantum Grid Transition Matrix',
    classification: 'SECRET',
    caveats: 'RELEASABLE TO JOINT STRATEGIC COMMAND',
    originatingOffice: 'Cybersecurity & Critical Infrastructure Security Agency',
    summary:
      'National power grid cryptographic migration timeline, hardware security module provisioning, and emergency failover protocols.',
    rawText: `================================================================================
SECRET // REL TO STRATCOM // INFRASTRUCTURE CRITICAL
DOCUMENT ID: CISA-PQC-GRID-2026-REV3
SECURITY CLASSIFICATION: SECRET

1. OVERVIEW
This document outlines the mandatory replacement of legacy RSA-2048 and ECDSA-P256
keys across all Regional Transmission Organizations (RTOs) with NIST FIPS 203 (ML-KEM)
and FIPS 204 (ML-DSA) compliant hardware enclaves.

2. KEY MIGRATION MILESTONES
- Substation SCADA Gateway Enclaves: 100% ML-DSA-65 firmware verification.
- Inter-Grid High Voltage Control Channels: 256-bit AES-GCM with post-quantum KEM session exchange.
- Emergency Black-Start Control Bus: Air-gapped manual key loading protocol.

3. AUDIT & FORENSIC TRACKING
Decryption events on this document require immediate non-repudiation signing by the
designated engineer's hardware key and registration on the secure facility ledger.
================================================================================`,
    visualPages: [],
    createdAt: 1790612000000,
  },
  {
    id: 'DOC-2026-MARITIME-SEC7',
    title: 'DIPLOMATIC & MARITIME PROTOCOL: Sector 7 Transit Corridors',
    classification: 'CONFIDENTIAL',
    caveats: 'AUTHORIZED BILLET ACCESS ONLY',
    originatingOffice: 'Bureau of Maritime Security & International Affairs',
    summary:
      'Coordinated civilian and naval maritime transit corridors, restricted coordinates, and international escort protocols.',
    rawText: `================================================================================
CONFIDENTIAL // RESTRICTED DISSEMINATION
BUREAU OF MARITIME SECURITY // STRATEGIC LOGISTICS
FILE: BMS-SEC7-CORRIDOR-ALPHA

1. SCOPE
Designation of deep-water acoustic safe lanes through Sector 7 international choke points.
All commercial convoys must register with designated escort vessels 72 hours prior to entry.

2. COORDINATE BOUNDARIES
- Entry Checkpoint Papa: 14°22'05" N, 112°45'18" E
- Mid-Transit Waypoint Sierra: 15°10'42" N, 114°02'30" E
- Exit Waypoint Victor: 16°05'12" N, 115°50'00" E

3. HANDLING INSTRUCTIONS
This file must be kept in encrypted local storage. Decryptions are monitored via
cryptographic session watermarking.
================================================================================`,
    visualPages: [],
    createdAt: 1790614000000,
  },
];

// In-Memory Recipients with Pre-Generated Authentic PQC Key Material
let INITIALIZED_RECIPIENTS: Recipient[] = [];
let initPromise: Promise<Recipient[]> | null = null;

export async function initializeRecipientsAndLedger(): Promise<Recipient[]> {
  if (INITIALIZED_RECIPIENTS.length > 0) {
    return INITIALIZED_RECIPIENTS;
  }
  if (!initPromise) {
    initPromise = (async () => {
      if (INITIALIZED_RECIPIENTS.length > 0) {
        return INITIALIZED_RECIPIENTS;
      }

      // Ensure genesis block is initialized (loaded from IndexedDB or created)
      await airGappedLedger.initGenesis();

      // Check persistent IndexedDB for recipients
      const savedRecipients = await airGappedStorage.getRecipients();
      if (savedRecipients && savedRecipients.length > 0) {
        const demoPassphrases: Record<string, string> = {
          'USR-ALICE-VANCE-01': 'AliceVance2026!',
          'USR-BOB-MARTINEZ-02': 'BobMartinez2026!',
          'USR-CHARLIE-CHEN-03': 'CharlieChen2026!',
          'USR-DIANA-ROSS-04': 'DianaRoss2026!',
        };

        const loaded: Recipient[] = [];
        let needsResave = false;

        for (const r of savedRecipients) {
          const pass = demoPassphrases[r.id] || 'SihSecurePass2026!';
          // Check if this is a legacy record with plaintext private keys
          if (r.keys.kemSecretKeyHex && r.keys.dsaSecretKeyHex && !r.keys.encryptedKeystore) {
            // MIGRATION: Encrypt plaintext keys into keystore and sanitize
            const keystoreRecord = await createUnifiedEncryptedKeystore(
              r.id,
              r.keys.keyFingerprint,
              hexToBytes(r.keys.kemSecretKeyHex),
              hexToBytes(r.keys.dsaSecretKeyHex),
              pass
            );
            await airGappedStorage.saveKeystore(keystoreRecord);
            r.keys.encryptedKeystore = keystoreRecord;
            needsResave = true;
          }

          // In-memory unlock for transitional demonstration view
          if (r.keys.encryptedKeystore) {
            try {
              const keystore = (await airGappedStorage.getKeystore(r.id)) || r.keys.encryptedKeystore;
              const unlocked = await unlockKeystoreRecord(keystore, pass);
              r.keys.kemSecretKeyHex = unlocked.kemSecretKeyHex;
              r.keys.dsaSecretKeyHex = unlocked.dsaSecretKeyHex;
              r.isUnlocked = true;
            } catch (unlockErr) {
              console.warn(`[SampleData] Could not unlock keystore for ${r.id}:`, unlockErr);
            }
          }

          loaded.push(r);
          airGappedLedger.registerRecipient(r);
        }

        if (needsResave) {
          const sanitized = loaded.map((r) =>
            sanitizeRecipientForPersistence(r, r.keys.encryptedKeystore!)
          );
          await airGappedStorage.saveRecipients(sanitized);
        }

        INITIALIZED_RECIPIENTS = loaded;
        return loaded;
      }

      const recipientProfiles = [
        {
          id: 'USR-ALICE-VANCE-01',
          name: 'Dr. Alice Vance',
          role: 'Chief Intelligence Analyst',
          organization: 'Directorate of Naval Intelligence',
          clearanceLevel: 'TOP SECRET // SCI' as const,
          avatarInitials: 'AV',
        },
        {
          id: 'USR-BOB-MARTINEZ-02',
          name: 'Col. Bob Martinez',
          role: 'Senior Logistics Director',
          organization: 'Joint Strategic Support Command',
          clearanceLevel: 'TOP SECRET // SCI' as const,
          avatarInitials: 'BM',
        },
        {
          id: 'USR-CHARLIE-CHEN-03',
          name: 'Cmdr. Charlie Chen',
          role: 'Cyber Defense Lead',
          organization: 'National Cyber Security Center',
          clearanceLevel: 'SECRET' as const,
          avatarInitials: 'CC',
        },
        {
          id: 'USR-DIANA-ROSS-04',
          name: 'Amb. Diana Ross',
          role: 'Foreign Affairs Security Liaison',
          organization: 'Diplomatic Protection Bureau',
          clearanceLevel: 'CONFIDENTIAL' as const,
          avatarInitials: 'DR',
        },
      ];

      const recipients: Recipient[] = [];

      for (const prof of recipientProfiles) {
        // Generate real NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) keypairs
        const keys = await generateRecipientPqcKeys();

        // Distinct demo passphrases for standard test personnel
        const demoPassphrases: Record<string, string> = {
          'USR-ALICE-VANCE-01': 'AliceVance2026!',
          'USR-BOB-MARTINEZ-02': 'BobMartinez2026!',
          'USR-CHARLIE-CHEN-03': 'CharlieChen2026!',
          'USR-DIANA-ROSS-04': 'DianaRoss2026!',
        };
        const pass = demoPassphrases[prof.id] || 'SihSecurePass2026!';

        // Create unified encrypted keystore at rest
        const keystoreRecord = await createUnifiedEncryptedKeystore(
          prof.id,
          keys.fingerprint,
          keys.kemSecretKey,
          keys.dsaSecretKey,
          pass
        );
        await airGappedStorage.saveKeystore(keystoreRecord);

        // In-memory unlocked state for transitional demonstration view
        const recipient: Recipient = {
          ...prof,
          isUnlocked: true,
          keys: {
            kemAlgorithm: 'ML-KEM-768',
            kemPublicKeyHex: bytesToHex(keys.kemPublicKey),
            kemSecretKeyHex: bytesToHex(keys.kemSecretKey),
            dsaAlgorithm: 'ML-DSA-65',
            dsaPublicKeyHex: bytesToHex(keys.dsaPublicKey),
            dsaSecretKeyHex: bytesToHex(keys.dsaSecretKey),
            encryptedKeystore: keystoreRecord,
            keyFingerprint: keys.fingerprint,
            registeredAt: Date.now() - 3600000 * 24 * 7, // 7 days ago
          },
        };

        recipients.push(recipient);
        airGappedLedger.registerRecipient(recipient);
      }

      // Persist ONLY sanitized recipient records (NO PLAINTEXT PRIVATE KEYS in persistent storage)
      const sanitizedRecipients = recipients.map((r) =>
        sanitizeRecipientForPersistence(r, r.keys.encryptedKeystore!)
      );
      await airGappedStorage.saveRecipients(sanitizedRecipients);
      INITIALIZED_RECIPIENTS = recipients;
      return recipients;
    })();
  }

  return await initPromise;
}
