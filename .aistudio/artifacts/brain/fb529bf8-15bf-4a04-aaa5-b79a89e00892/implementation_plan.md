# Implementation Plan: Complete Settings Page — SIH 26237

Build a defense-grade, production-quality **Settings Page** for the SIH 26237 Post-Quantum Document Enclave (*AEGIS-PQC: Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution*), providing rigorous operational controls, live cryptographic self-tests, forensic watermarking parameters, DLT consensus inspection, air-gapped storage backup/restore, and security health diagnostics.

### User Review & Critical Decisions

> [!IMPORTANT]
> The Settings page will strictly integrate with the application's actual cryptographic engines (`@noble/post-quantum`, Web Crypto API), the authoritative air-gapped storage adapter (`AirGappedStorage` / IndexedDB), the 4-node permissioned ledger (`airGappedLedger`), and the tamper-evident audit service (`auditService`). All self-tests and diagnostic checks will execute genuine cryptographic operations rather than simulated animations.

- **Confirmed Architecture**: Multi-tab in-page navigation (General Preferences, Cryptographic Engine, Forensic Watermarking, DLT Consensus, Storage & Backup, and Diagnostics & Health).
- **Storage Strategy**: Enclave preferences (density, default landing tab, safety confirmation flags, session timeout) will be persisted in `localStorage` under `sih_enclave_settings_v1` and loaded into global application state upon boot.
- **Cryptographic Grounding**: Algorithm parameters are displayed as authoritative read-only configurations, complemented by an interactive **Cryptographic Diagnostic Runner** that conducts live Web Crypto AES-256-GCM, NIST FIPS 203 ML-KEM-768, NIST FIPS 204 ML-DSA-65, and SHA-256/HKDF self-tests in real-time.
- **Storage Sanitation**: Two distinct reset pathways:
  1. *Reset Demo Session*: Restores demo recipients, default documents, and initial blocks while clearing active packages and simulated leaks.
  2. *Secure Air-Gap Storage Wipe*: Requires typing a confirmation phrase (`WIPE-ENCLAVE`) before atomically purging all IndexedDB stores (`blocks`, `recipients`, `packages`, `keystores`, `audit_logs`) and reset storage partitions.

---

### 1. Overview & Core Concept

- **What It Does**: Unifies system configuration, hardware/session isolation boundaries, post-quantum cryptographic verification, consensus parameters, and offline persistence management into an authoritative control console.
- **Target Audience / Persona**: Defense cryptographers, security auditors, intelligence workstation operators, and enclave administrators managing air-gapped classified document distribution.
- **Key Value**: Delivers complete operational observability and fine-grained system controls without exposing private key material or weakening the air-gapped security boundary.

---

### 2. User Experience & Visual Design

#### Key User Flows
1. **Preferences Customization**: The operator selects the default landing view (e.g. Overview vs Sender Studio vs Audit Center), adjusts interface density (Comfortable vs Compact workstation mode), configures session inactivity timeouts, and enables/disables destructive action warnings. Changes persist immediately.
2. **Cryptographic Verification**: The operator navigates to the Cryptography tab, reviews the NIST FIPS 203/204 parameters, and triggers **"Run Cryptographic Diagnostics"**. The system executes real in-browser key encapsulation, lattice signature verification, and AES-GCM AAD enforcement, reporting per-algorithm pass/fail status and roundtrip latency in milliseconds.
3. **Forensic Steganography Inspection**: The operator explores watermarking parameters (zero-width Unicode alphabet, 16-bit sync word `0xA55A`, CRC-16 checksum, 32-byte payload binary layout) and tests the interactive watermark sampler to verify invisible payload encoding without visual corruption.
4. **Consensus & DLT Auditing**: The operator inspects the 4 validator enclave nodes (Alpha, Bravo, Gamma, Delta), examines their public attestation keys and socket ports, reviews the 3-of-4 quorum threshold, and runs a live **Chain Integrity Verification** that checks Merkle roots and SHA-256 block hash links.
5. **Air-Gap Backup & Restoration**: The operator views live storage partition metrics (record counts and memory sizes across IndexedDB object stores), downloads a verifiable `.json` Enclave Backup Archive, or restores previous session state via secure dropzone.

#### Visual Identity & Theme
- **Aesthetic Direction**: Restrained, defense-grade cryptographic workstation; high visual density, flat surfaces, crisp hairline borders (`border-slate-200/90`), subtle slate palette with emerald verification badges and indigo primary accents.
- **Color Palette & Mood**:
  - Dominant Canvas: `bg-slate-50` / `bg-white`
  - Structural Borders: `border-slate-200/90` and `border-slate-100`
  - Typography: `text-slate-900` (headings), `text-slate-600` (labels), `text-slate-400` (secondary metadata)
  - Status Semantics: Emerald (`text-emerald-700 bg-emerald-50 border-emerald-200`) for verified integrity, Amber for warnings, Rose for failed or destructive states.
- **Typography & Hierarchy**:
  - Headings: Bold tracking-tight display typography matching `designSystem.tsx`.
  - Data Values & Hashes: Monospace tabular numerals (`font-mono text-xs tabular-nums`).
  - Zero-pill discipline: Unboxed metadata tags separated by `·` or `/`.
- **Component Styling & Layout**:
  - In-page vertical sidebar navigation (left 220px on desktop) paired with a responsive main content pane.
  - Consistent use of `designSystem.tsx` primitives (`PageShell`, `PageHeader`, `Section`, `PrimaryButton`, `SecondaryButton`, `DangerButton`, `StatusBadge`, `KeyValueRow`, `HashDisplay`).

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1: Real In-Browser Cryptographic Self-Tests vs Mock Status Indicators**
  - *Chosen Approach*: The diagnostic runner generates real ephemeral ML-KEM-768 keypairs, encapsulates and decapsulates shared secrets, signs and verifies test digests with ML-DSA-65, and checks AES-256-GCM authenticated data.
  - *Why*: In a defense-grade enclave application, claiming an algorithm is operational without cryptographic proof violates zero-trust principles.
  - *Alternatives Considered*: Hardcoded status tables were rejected as deceptive.

- **Decision 2: Two-Tier Storage Reset (Demo Session Reset vs Total Enclave Wipe)**
  - *Chosen Approach*: Provide a soft "Reset Demo Session" (quick reset for demonstrations) and a distinct, red-bordered "Air-Gap Storage Wipe" requiring typed confirmation (`WIPE-ENCLAVE`).
  - *Why*: Prevents accidental loss of real audit logs or ingested packages during evaluation while offering full data sanitization when required.
  - *Alternatives Considered*: A single ambiguous reset button that creates operator uncertainty.

- **Decision 3: Complete Backup Archive Serialization via Existing Services**
  - *Chosen Approach*: The export tool aggregates blocks from `airGappedLedger`, packages from `airGappedStorage`, audit logs from `auditService`, and certificates into a single canonical JSON payload with SHA-256 manifest integrity.
  - *Why*: Allows operators to export an air-gapped enclave snapshot to external media (e.g. offline USB drive) and restore it reliably on another isolated machine.

---

### 4. Technical Architecture & Data Strategy

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SettingsView Architecture                       │
└────────────────────────────────────────────────────────────────────────┘
                                    │
       ┌────────────────────────────┼────────────────────────────┐
       ▼                            ▼                            ▼
┌──────────────┐             ┌──────────────┐             ┌──────────────┐
│  Navigation  │             │ Active Pane  │             │ Persistence  │
│  Sidebar     │             │  Controller  │             │   Adapter    │
└──────┬───────┘             └──────┬───────┘             └──────┬───────┘
       │                            │                            │
       ├─ General Preferences       ├─ Render Section Component  ├─ LocalStorage
       ├─ Cryptographic Engine      ├─ Trigger Live Self-Tests   ├─ IndexedDB
       ├─ Forensic Watermarking     ├─ Verify DLT Hash Chains    ├─ Session Mgr
       ├─ DLT Consensus (4 Nodes)   ├─ Calculate Store Metrics   └───────────────
       ├─ Storage & Backup          └─ Execute Sanitization
       └─ Diagnostics & Audit
```

#### Settings Categories & Component Mapping

1. **General Preferences (`GeneralPreferencesSection`)**:
   - `defaultTab`: Default landing route on application startup (`overview`, `documents`, `decrypt`, `forensics`, `ledger`, `audit`).
   - `interfaceDensity`: `comfortable` vs `compact` (adjusts table row paddings and spacing tokens).
   - `confirmDestructiveActions`: Boolean flag guarding package revoking, quarantine, and resets.
   - `sessionTimeoutMinutes`: Inactivity timeout (5m, 15m, 30m, 60m) mapped to `sessionManager.setConfig()`.
   - `autoLockOnBlur`: Optional auto-lock when window loses focus.

2. **Cryptographic Parameters & Self-Test (`CryptoSettingsSection`)**:
   - Read-only table of active cryptographic standards:
     - NIST FIPS 203 (ML-KEM-768) — 1,184-byte public key, 1,088-byte ciphertext, 32-byte shared secret.
     - NIST FIPS 204 (ML-DSA-65) — 1,952-byte public key, 3,309-byte signature.
     - Bulk Encryption — AES-256-GCM with 96-bit random IV, 128-bit authentication tag, strict canonical AAD document binding.
     - Key Derivation — HKDF-SHA256 (RFC 5869) with zeroization memory hygiene.
   - **Interactive Live Self-Test Suite**:
     - Test 1: Web Crypto AES-256-GCM encryption and authenticated decryption.
     - Test 2: AES-GCM strict AAD mismatch rejection (verifies VULN-02 remediation).
     - Test 3: NIST FIPS 203 ML-KEM-768 keygen, encapsulation, and decapsulation matching.
     - Test 4: NIST FIPS 204 ML-DSA-65 signing and lattice signature verification.
     - Test 5: HKDF-SHA256 key derivation and memory buffer zeroization.
     - Displays execution status, timestamp, and duration per test.

3. **Forensic Watermarking Configuration (`WatermarkSettingsSection`)**:
   - Watermarking channel specification:
     - Text Layer: Invisible 4-symbol zero-width Unicode steganography (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`).
     - Binary Layout: 32-byte frame consisting of 16-bit sync word (`0xA55A`), 16-byte session UUID, 8-byte recipient fingerprint, 4-byte Unix timestamp, and 16-bit CRC-16 checksum.
     - PDF Vector Layer: Invisible low-luminance PDF metadata and vector micro-shift modulation.
   - **Interactive Watermark Sampler**:
     - Live simulation allowing the operator to type test text and view invisible payload encoding and blind extraction extraction results with bit-level validation.

4. **DLT Ledger & Consensus Settings (`ConsensusSettingsSection`)**:
   - 4-Node Permissioned Validator Cluster details:
     - Node Alpha (`val-alpha-01`): Primary Consensus Node, port 7001/8001.
     - Node Bravo (`val-bravo-02`): Secondary Verification Node, port 7002/8002.
     - Node Gamma (`val-gamma-03`): Audit Authority Node, port 7003/8003.
     - Node Delta (`val-delta-04`): Redundant Consensus Node, port 7004/8004.
   - Quorum Parameters: Threshold of 3 out of 4 nodes required (75% BFT Byzantine agreement).
   - Chain Status & Metrics: Current height, block hash of head, Genesis block hash (`0000000000000000...`).
   - **Chain Health Verifier**: Button to run `airGappedLedger.verifyLedgerIntegrity()` live and report validation results.

5. **Storage, Air-Gap & Backup Management (`StorageBackupSection`)**:
   - Storage Partition Telemetry:
     - Query IndexedDB object stores (`blocks`, `recipients`, `packages`, `keystores`, `audit_logs`) and local storage collections.
     - Render total record counts, estimated storage usage, and database version (`v1`).
   - **Export Enclave Backup Archive**:
     - Serializes complete system state (blocks, packages, audit log records, forensic dossiers, certificates) into a validated JSON backup bundle with timestamped file download (`sih-enclave-backup-<ISO>.json`).
   - **Restore Enclave Backup**:
     - File dropzone/picker to upload and restore `.json` backup archive with schema validation and sanitization.
   - **Sanitization Controls**:
     - Button 1: "Reset Demo Session" (calls existing `onResetSession` handler).
     - Button 2: "Purge & Wipe Air-Gap Storage" (with modal requiring typed confirmation phrase `WIPE-ENCLAVE`).

6. **Audit & Diagnostics Hub (`AuditDiagnosticsSection`)**:
   - Audit hash chain status: RFC 5424 structured events, continuous SHA-256 hash chaining ($E_n = \text{SHA256}(E_{n-1} \parallel \text{canonical}(E_n))$).
   - **Live Audit Integrity Check**: Invokes `auditService.verifyAuditIntegrity()` and displays total events inspected and tamper verification status.
   - NIST CSF 2.0 Anomaly Detection Rule list (authoritative enforcement status).

---

### Verification & Testing Plan

1. **Build & Compilation**: Run `compile_applet` and `lint_applet` to ensure clean TypeScript compilation with zero type errors.
2. **Preference Persistence**: Change default landing view, interface density, and session timeout; reload page and verify preferences are restored from `localStorage`.
3. **Cryptographic Self-Tests**: Run the live diagnostics suite and verify that all 5 tests (AES-256-GCM, AAD rejection, ML-KEM-768, ML-DSA-65, HKDF zeroization) execute and pass in under 200ms.
4. **Watermark Engine Sampler**: Test sample text watermarking and verify blind extraction recovers the exact embedded test payload.
5. **Consensus & DLT Verification**: Run chain integrity check against `airGappedLedger` and confirm successful Merkle root and block hash verification.
6. **Storage Analytics & Export/Import**: Check that storage counts reflect real IndexedDB items, test downloading the JSON backup archive, and test the reset session confirmation.
