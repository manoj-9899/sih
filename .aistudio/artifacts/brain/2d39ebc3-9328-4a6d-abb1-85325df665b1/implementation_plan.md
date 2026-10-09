# UI/UX Redesign Plan: Production Security & Digital Forensics Platform

## 1. Product Principle & Design Objective

### Core Principle
> **"Simple surface. Sophisticated system underneath."**

The interface must present clear, human-understandable workflows and outcomes by default. Dense cryptographic specifications, 64-character hexadecimal values, raw signatures, Merkle inclusion proofs, and validator consensus mathematics are preserved completely, but **progressively disclosed** through clean expandable drawers, technical detail accordions, and evidence inspector views.

### Design Objective
- **Aesthetic**: Minimalist, calm, trustworthy, precise, modern, Swiss/laboratory clean.
- **Color Palette**: Light near-white backgrounds (`bg-slate-50` / `bg-white`), dark slate typography (`text-slate-900` / `text-slate-500`), restrained indigo primary accent (`bg-indigo-600`), and clear status indicators (emerald green for verified/healthy, amber for pending/attention, rose for failed/tampered).
- **Typography**: Inter (sans-serif) for general copy, headings, and tables. Monospace reserved strictly for hashes, fingerprints, public keys, and cryptographic IDs.
- **Tone & Terminology**: Real-world digital forensics and document security terminology. Eradicate fictional military roleplay (*"SCIF Alpha"*, *"Strategic Anti-Air Grid"*, *"Tactical Node"*, *"Enclave Barrier"*, *"Cyber Defense Lead"*).

---

## 2. Navigation Architecture & Route Reorganization

The navigation structure is updated to the clean 4-tier hierarchy:

```
WORKSPACE
├── Overview         (Was: Mission Control)
├── Documents        (Was: Sender Studio)
├── Recipients       (Dedicated recipient management & key states)
└── Decrypt          (Was: Recipient Portal)

INVESTIGATION
├── Forensics        (Was: Forensic Studio)
└── Ledger           (Was: Air-Gapped DLT)

SECURITY
├── Identity         (Was: PQC Registry)
└── Verification     (Was: Security Stress Lab)

SYSTEM
└── Settings         (Environment, offline status, quorum parameters)
```

*Note: The active navigation state is managed via `ActiveTab`: `'overview' | 'documents' | 'recipients' | 'decrypt' | 'forensics' | 'ledger' | 'identity' | 'verification' | 'settings'`.*

---

## 3. Reusable Component System (`src/components/ui/designSystem.tsx`)

A unified component library will replace disparate ad-hoc markup across all views:

1. **Layout**:
   * `PageShell`: Standard full-height page wrapper with consistent padding (`p-6 sm:p-8 lg:p-10`) and max-width boundaries (`max-w-6xl`).
   * `PageHeader`: Consistent top header: `title` (large, semi-bold text), `description` (one-line muted explanation), and optional right-aligned primary `action`.
   * `Section`: Standard content container with subtle borders (`border-slate-200/80`), white background, and generous internal padding.
   * `Divider`: Minimal hairline divider.

2. **Buttons & Actions**:
   * `PrimaryButton`: High-contrast solid button with restrained indigo/slate focus.
   * `SecondaryButton`: Clean bordered button for secondary actions.
   * `DangerButton`: Red subtle/outline button for destructive actions (e.g. tamper simulation).
   * `TextButton` / `IconButton`: Minimal utility buttons.

3. **Status & Verification**:
   * `StatusBadge`: Clean status indicator (`verified`, `pending`, `tampered`, `inactive`).
   * `VerificationBadge`: Compact verified badge with green tick for signatures and ledger states.

4. **Progressive Disclosure & Technical Details**:
   * `TechnicalDetails`: Expandable accordion container hidden by default: *"[ View technical details ]"*.
   * `KeyValueRow`: Horizontal key-value layout with monospace values and quick-copy action.
   * `HashDisplay`: Truncated monospace hash with one-click copy (`0x7a9f...9a0b`).
   * `DetailsDrawer`: Slide-over drawer for in-depth cryptographic inspection.

5. **Workflows & States**:
   * `EmptyState`: Friendly empty state with icon, message, and direct primary action button.
   * `LoadingState`: Minimal spinner with contextual label.
   * `ErrorState`: Clear error description with cause and remediation step.

---

## 4. Screen-by-Screen Redesign Specifications

### Screen 1: Overview (`OverviewView.tsx`)
* **Header**: "Overview" — *System status, cryptographic readiness, and recent activity.*
* **Top Status Strip**: 4 compact summary metrics (not oversized cards):
  1. *System status*: Offline / Air-gapped (Local environment verified)
  2. *Ledger health*: 4/4 Validator nodes active · Quorum operational
  3. *Cryptographic readiness*: NIST FIPS 203 (ML-KEM-768) & FIPS 204 (ML-DSA-65) active
  4. *Protected documents*: Active package count & recipient registrations
* **Recent Provenance Activity**: Simple, scannable table/list showing recent decryption events, timestamps, recipient, block height, and signature verification status.
* **Quick Actions**: "Distribute document" and "Analyze document".

### Screen 2: Documents (`DocumentsView.tsx`, refactored from `SenderStudio.tsx`)
* **Header**: "Documents" — *Manage protected documents and prepare secure distribution.*
* **Primary Action**: "Upload document" (opens clean modal).
* **Document List**: Minimal table/card list showing:
  * Title, Classification tag (`TOP SECRET // SCI`, `SECRET`, `CONFIDENTIAL`), File type (`PDF`), Size, Updated date.
* **Selection Detail Panel**: When a document is selected:
  * Document summary, recipient checklist (Alice Vance, Bob Martinez, Charlie Chen), and security summary: `ML-KEM-768 · AES-256-GCM`.
  * Primary Action: **"Encrypt & prepare distribution"**.
  * Expandable *Technical details* (IV, GCM tag, CEK derivation metadata).

### Screen 3: Recipients (`RecipientsView.tsx`, new dedicated screen)
* **Header**: "Recipients" — *Manage authorized recipients and local cryptographic identities.*
* **Recipient Rows**:
  * Name, Role, Organization, Status (`Active`), Algorithms (`ML-KEM-768 · ML-DSA-65`), Key Fingerprint (short).
* **Recipient Inspector**:
  * Identity status, local private-key protection status, key registered date.
  * *Technical details* drawer with public keys and exportable public credentials.
* **Enrollment Action**: "Add recipient" with locally generated ML-KEM and ML-DSA keys.

### Screen 4: Decrypt (`DecryptView.tsx`, refactored from `RecipientPortal.tsx`)
* **Header**: "Decrypt document" — *Decrypt locally and create a signed provenance record.*
* **Session Context**: Clean badge showing current local identity (*Signed in as Dr. Alice Vance* with an easy switcher for demonstration testing).
* **Pre-decryption Summary**:
  * Document ready for decryption.
  * Guarantee checklist:
    * ✓ Decrypted in local memory
    * ✓ Unique forensic fingerprint created
    * ✓ Decryption event digitally signed
    * ✓ Provenance recorded in offline ledger
  * Primary Action: **"Decrypt document"**.
* **During Decryption**: Clean sequential checklist showing progress without permanent card clutter:
  * ✓ Verify access $\rightarrow$ ✓ Recover encryption key $\rightarrow$ ✓ Decrypt document $\rightarrow$ ✓ Create forensic fingerprint $\rightarrow$ ✓ Sign decryption event $\rightarrow$ ✓ Record provenance.
* **Post-Decryption View**:
  * Clean document viewport with high legibility.
  * Top bar showing: Forensic fingerprint (`WM-7A4C••••92E1`), Provenance (`Verified`), Ledger (`Block #X`), Signature (`Valid`).
  * Action: "Download decrypted file" and "Simulate anonymous leak" (for demonstration).
  * Expandable *Technical details* showing watermark payload diagnostics.

### Screen 5: Forensics (`ForensicsView.tsx`, refactored from `ForensicStudio.tsx`)
* **Header**: "Forensic verification" — *Upload a leaked document to identify its originating decryption event.*
* **Input Area**: Minimalist document dropzone:
  * *"Drop leaked document here or choose a file"* with quick-sample buttons (*"Load Bob's leaked copy"*).
  * Primary Action: **"Analyze document"**.
* **Forensic Attribution Result (Dominates the page)**:
  * High-visibility status banner: **MATCH FOUND** (or No Watermark Detected).
  * Attributed Recipient: Name, Role, Avatar.
  * Decryption event reference: `EVT-2026-00482`.
  * Forensic fingerprint: `WM-7A4C••••92E1`.
  * Signature: `✓ Valid (ML-DSA-65)`.
  * Ledger evidence: `✓ Verified in Block #X`.
* **Evidence Chain**:
  * Watermark extracted $\rightarrow$ Matched to decryption event $\rightarrow$ Recipient signature verified $\rightarrow$ Ledger evidence verified.
* **Progressive Disclosure**: *Technical details* contains raw zero-width character extraction metrics, PSNR estimate, and Merkle inclusion proof.

### Screen 6: Ledger (`LedgerView.tsx`, refactored from `DltExplorer.tsx`)
* **Header**: "Ledger" — *Tamper-evident provenance for verified decryption events.*
* **Top Status Strip**:
  * Ledger integrity: `✓ Verified` · Quorum health: `4/4 Validator nodes active` · Total blocks: `N`.
* **Compact Validator Grid**:
  * 4 Validator cards (Alpha, Bravo, Gamma, Delta) showing node status (`Online`), enclave location, and validated block counts.
* **Recent Provenance Timeline**:
  * Clean event stream showing: Recipient name, Document title, Timestamp, Block height, and Signature verification badge.
  * Clicking an event opens the full evidence drawer.
* **Audit & Resilience Bench**:
  * Clean action: "Audit entire chain".
  * Test trigger: "Simulate administrative tamper" with immediate recovery action "Restore quorum integrity".
* **Progressive Disclosure**: Raw block hashes, previous block hashes, Merkle roots, and validator signatures hidden behind *Technical details*.

### Screen 7: Identity (`IdentityView.tsx`, refactored from `PqcRegistry.tsx`)
* **Header**: "Cryptographic identities" — *Manage post-quantum identities used to protect access and verify decryption events.*
* **Identity Roster**: Clean list with avatar, name, role, status, and algorithms.
* **Identity Detail Card**:
  * Key exchange: `ML-KEM-768` (Public key registered).
  * Digital signature: `ML-DSA-65` (Public key registered).
  * Private key: `Protected locally in encrypted keystore`.
* **Enrollment Modal**:
  * "Add recipient": Name, Role, Organization, Clearance.
  * "Generate cryptographic identity" executes genuine `ml_kem768.keygen()` and `ml_dsa65.keygen()`.
* **Progressive Disclosure**: Full public key hex strings and raw fingerprints placed inside *View technical details*.

### Screen 8: Verification (`VerificationView.tsx`, refactored from `SecurityTestHarness.tsx`)
* **Header**: "Security verification" — *Test the platform against defined attack scenarios.*
* **Summary Banner**: 7 tests · 7 passed · Primary action: **"Run all tests"**.
* **4 Organized Categories**:
  1. *Cryptography*: Unauthorized decryption · Cross-recipient isolation · Ciphertext bit-flip tampering.
  2. *Attribution*: Forged recipient signature rejection.
  3. *Ledger*: Historical ledger tamper detection.
  4. *Watermarking*: False-positive detection · Watermark corruption resistance.
* **Test Row Layout**:
  * Test title, one-line explanation, **Expected result** (replaces "Security guarantee"), Status badge (`Passed`), and button: *"[ View details ]"*.
  * Expansion shows isolated execution logs without modifying real demo data.

### Screen 9: Settings (`SettingsView.tsx`, new dedicated screen)
* **Header**: "Settings" — *System configuration and environment parameters.*
* **Clean Grouped Settings**:
  * *Environment*: Air-gapped / offline local execution.
  * *Storage*: Local IndexedDB persistence with session reset option.
  * *Consensus*: 3/4 Quorum threshold configuration.
  * *Cryptography*: NIST FIPS 203 & FIPS 204 active parameter sets.
  * *System*: Application version `v2.4.0-pqc`.

---

## 5. Layout, Sidebar, and Responsive Implementation

1. **Fixed Sidebar Architecture**:
   * Desktop (`lg:`): Sidebar is fixed (`fixed inset-y-0 left-0 w-64`), with main content wrapper offset by `ml-64`. Main area scrolls independently without shifting the sidebar.
   * Mobile/Tablet: Sleek top bar with hamburger menu opening a backdrop-blurred slide-in navigation drawer.
2. **Interactive Tour Compatibility**:
   * Preserves existing `TOUR_STEPS` and `FloatingMissionGuide.tsx` seamlessly with updated route keys (`overview`, `documents`, `decrypt`, `forensics`, `ledger`, `identity`, `verification`).

---

## 6. Implementation Steps

1. **Phase 1**: Build unified design system primitives (`src/components/ui/designSystem.tsx`) providing `PageShell`, `PageHeader`, `Section`, buttons, badges, and `TechnicalDetails`.
2. **Phase 2**: Refactor global navigation (`Sidebar.tsx`, `Navbar.tsx`, `TopBar.tsx`, and `App.tsx`) with updated route keys and fixed-sidebar layout.
3. **Phase 3**: Create/update the 9 screens (`OverviewView`, `DocumentsView`, `RecipientsView`, `DecryptView`, `ForensicsView`, `LedgerView`, `IdentityView`, `VerificationView`, `SettingsView`).
4. **Phase 4**: Update `tour.ts` navigation targets and ensure all existing backend services (`DistributionService`, `airGappedLedger`, `airGappedStorage`, `pqc`) remain 100% untouched.
5. **Phase 5**: Verify responsive layout, test execution, run `npm run lint`, and verify production build with `compile_applet`.
