# AEGIS-PQC Overview Page Redesign Plan

Redesign the existing **Overview page** in AEGIS-PQC (*Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution*) to provide a clear, beginner-friendly starting point without sacrificing its defense-grade workstation aesthetic.

## User Review & Critical Decisions

> [!IMPORTANT]
> **Confirmed Choices from Phase 1 Clarifications:**
> - **Workflow Presentation**: Numbered vertical cards with clear step descriptions, concise instructions, expected outputs, and direct action buttons.
> - **Information Hierarchy**: Live system status cards pinned at top, followed by the "Start Here" introduction, the 8-step workflow guide, beginner distinctions & common mistakes, recent provenance activity, and a collapsible technical drawer.

---

## 1. Overview & Core Concept

- **What It Does**: Explains AEGIS-PQC in plain English: how documents are encrypted once for multiple authorized recipients, how successful local decryption embeds recipient/session-specific forensic watermarks, and how that evidence is recorded to an immutable ledger for later investigation.
- **Target Audience / Persona**: Security operators, forensic analysts, and compliance officers who need to navigate the enclave without getting lost in low-level cryptographic jargon on first launch.
- **Key Value**: Provides an actionable roadmap from Identity setup to Forensic investigation, making the purpose of `.sihpkg` packages and watermarked PDFs crystal clear.

---

## 2. User Experience & Visual Design

### Page Layout Flow
1. **Header Zone**: Page title and subtitle with primary shortcut buttons ("Distribute Document", "Analyze Document").
2. **Live Enclave Status Cards (Top Tier)**:
   - *Environment*: Air-Gapped Local (hardware-isolated status).
   - *Ledger Health*: Live block count and 4/4 validator node quorum status.
   - *Cryptographic Readiness*: FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65).
   - *Protected Documents*: Live count of managed documents and enrolled identities.
3. **"Start Here" Introduction**:
   - Plain-English introduction explaining what the workstation does and how the attribution loop works.
4. **Complete 8-Step Actionable Workflow Guide**:
   - **Step 1 — Review Identity**: Review cryptographic keys and active enclave operator identity (`onNavigateTab('identity')`).
   - **Step 2 — Review Recipients**: Confirm authorized recipient keys and enrollment status (`onNavigateTab('recipients')`).
   - **Step 3 — Encrypt and Export a Document**: Select PDF, choose recipients, generate package, export `.sihpkg` (`onNavigateTab('documents')`).
   - **Step 4 — Transfer the Package**: Transfer the `.sihpkg` package to the recipient via air-gapped media or secure drop (`onNavigateTab('documents')` / `onNavigateTab('decrypt')`).
   - **Step 5 — Decrypt as the Intended Recipient**: Import `.sihpkg`, authenticate, perform decryption, produce watermarked PDF (`onNavigateTab('decrypt')`).
   - **Step 6 — Investigate Forensic Evidence**: Upload suspected leaked PDF, extract steganographic watermark, inspect attribution (`onNavigateTab('forensics')`).
   - **Step 7 — Verify Supporting Evidence**: Run verification checks on certificates, hashes, and quorum (`onNavigateTab('verification')`).
   - **Step 8 — Inspect Provenance and Audit Records**: Review chronological ledger blocks and tamper-evident audit logs (`onNavigateTab('ledger')` / `onNavigateTab('audit')`).
5. **Beginner Guidance & Common Pitfalls Box**:
   - Distinction between `.sihpkg` (encrypted transit container) and watermarked PDF (decrypted plaintext output).
   - Explanation that watermark detection is not equal to cryptographically verified attribution until ledger cross-check succeeds.
   - Requirement to treat verification failures as genuine security alerts.
6. **Recent Provenance Activity (Preserved Live Section)**:
   - Live stream of recent decryption events from `airGappedLedger.getChain()`, with timestamp, recipient name, document title, watermark ID, and verification badges.
7. **Collapsible Technical Specifications**:
   - Cryptographic algorithms (FIPS 203 ML-KEM-768, FIPS 204 ML-DSA-65, AES-256-GCM, HKDF-SHA256, 4-Node BFT Quorum).

### Visual Styling & Tokens
- **Theme**: Defense-grade workstation aesthetic using Tailwind CSS (`bg-slate-50`, `border-slate-200`, `text-slate-900`, `text-slate-500`, `bg-indigo-600` primary buttons).
- **Zero-Pill Discipline**: Status and metadata rendered with clean typographic separators and unboxed badges.
- **Tabular Figures**: All counts, block numbers, timestamps, and IDs set in `tabular-nums` and `font-mono`.

---

## 3. Key Product Decisions & Trade-Offs

- **State-Grounded Status**: Workflow steps only indicate "Completed" if genuine state exists (e.g. `activePackage !== null` for Step 3, `allEvents.length > 0` for Step 5). Steps without completion state show "Action Ready" with direct navigation.
- **Strict Boundary**: Changes are strictly confined to `src/components/OverviewView.tsx`. No crypto, consensus, or persistence code is altered.
- **Preservation of Existing Data Sources**: Uses existing props `documents`, `recipients`, `activePackage`, `onNavigateTab`, and live query `airGappedLedger.getChain()`.

---

## 4. Technical Architecture & Component Structure

```
┌─────────────────────────────────────────────────────────────┐
│                       OverviewView                          │
├─────────────────────────────────────────────────────────────┤
│ 1. PageHeader (Title, subtitle, quick actions)              │
│ 2. Live Status Cards (Air-gapped, Ledger, FIPS, Documents)  │
│ 3. "Start Here" Mission Statement & Workflow Introduction   │
│ 4. 8-Step Actionable Workflow Container                     │
│    ├── Step 1: Identity & Key Check       -> [Identity]     │
│    ├── Step 2: Recipient Directory        -> [Recipients]   │
│    ├── Step 3: Encrypt & Export Package   -> [Documents]    │
│    ├── Step 4: Transfer .sihpkg Package   -> [Decrypt/Docs] │
│    ├── Step 5: Authorized Decryption      -> [Decrypt]      │
│    ├── Step 6: Forensic Attribution       -> [Forensics]    │
│    ├── Step 7: Cryptographic Verification -> [Verification] │
│    └── Step 8: Provenance & Audit Ledger  -> [Ledger/Audit] │
│ 5. Beginner Principles & Common Pitfalls Callout Grid       │
│ 6. Recent Provenance Activity (Live Ledger Transactions)    │
│ 7. Collapsible Technical Details (FIPS 203/204 specs)       │
└─────────────────────────────────────────────────────────────┘
```
