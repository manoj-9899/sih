# Practical Beginner Demo Guide: Post-Quantum Document Enclave & Forensic Attribution System (SIH26237)

Welcome to the **SIH26237 Post-Quantum Document Enclave & Forensic Attribution Workstation**.

This step-by-step practical guide is written for anyone seeing or evaluating this project for the first time. By following this guide from start to finish, you will understand:
1. **WHAT you are doing** on screen at every single click.
2. **WHAT is happening internally** across the cryptographic and ledger engines.
3. **WHY this step matters** in solving the core challenge of multi-recipient leak attribution.

---

## Table of Contents
1. [Core Cryptography Concepts Explained in Plain English](#1-core-cryptography-concepts-explained-in-plain-english)
2. [Starting the Application](#2-starting-the-application)
3. [Understanding the Application Interface](#3-understanding-the-application-interface)
4. [Step-by-Step Practical Walkthrough (The Complete End-to-End Flow)](#4-step-by-step-practical-walkthrough)
   - [Step 1 — Start the System and Understand the Mode Switch](#step-1--start-the-system-and-understand-the-mode-switch)
   - [Step 2 — Open Sender Studio & Review Available Documents](#step-2--open-sender-studio--review-available-documents)
   - [Step 3 — Ingest or Create a Custom Document (Optional)](#step-3--ingest-or-create-a-custom-document-optional)
   - [Step 4 — Select Authorized Recipients](#step-4--select-authorized-recipients)
   - [Step 5 — Create the Encrypted Broadcast Package](#step-5--create-the-encrypted-broadcast-package)
   - [Step 6 — Inspect and Understand the Package Structure](#step-6--inspect-and-understand-the-package-structure)
   - [Step 7 — Open Recipient Portal & Select an Operator Identity](#step-7--open-recipient-portal--select-an-operator-identity)
   - [Step 8 — Test Unauthorized Access (Negative Security Gate)](#step-8--test-unauthorized-access-negative-security-gate)
   - [Step 9 — Decrypt Document as an Authorized Recipient](#step-9--decrypt-document-as-an-authorized-recipient)
   - [Step 10 — Understand Dynamic Watermarking and the Provenance Signature](#step-10--understand-dynamic-watermarking-and-the-provenance-signature)
   - [Step 11 — View Plaintext & Inspect the Invisible Forensic Channel](#step-11--view-plaintext--inspect-the-invisible-forensic-channel)
   - [Step 12 — Simulate a Document Leak](#step-12--simulate-a-document-leak)
   - [Step 13 — Open Forensic Studio & Ingest the Leaked Artifact](#step-13--open-forensic-studio--ingest-the-leaked-artifact)
   - [Step 14 — Execute Blind Forensic Attribution](#step-14--execute-blind-forensic-attribution)
   - [Step 15 — Verify the Cryptographic Evidence Chain](#step-15--verify-the-cryptographic-evidence-chain)
   - [Step 16 — Download Court-Ready Attribution Certificate](#step-16--download-court-ready-attribution-certificate)
   - [Step 17 — Inspect the Immutable Ledger in DLT Explorer](#step-17--inspect-the-immutable-ledger-in-dlt-explorer)
   - [Step 18 — Simulate and Catch a Rogue Administrator Database Tamper](#step-18--simulate-and-catch-a-rogue-administrator-database-tamper)
   - [Step 19 — Inspect Post-Quantum Keys in PQC Registry](#step-19--inspect-post-quantum-keys-in-pqc-registry)
   - [Step 20 — Run Adversarial Tests in Attack Lab](#step-20--run-adversarial-tests-in-attack-lab)
5. [Full Demo Scenario (End-to-End Narrative)](#5-full-demo-scenario)
6. [Troubleshooting Common Demo Issues](#6-troubleshooting-common-demo-issues)
7. [What You Should Understand After Completing the Demo](#7-what-you-should-understand-after-completing-the-demo)

---

## 1. Core Cryptography Concepts Explained in Plain English

Before clicking any buttons, here is a quick overview of the key technologies used in this system:

| Term | What It Is in This Project | Why It Matters |
| :--- | :--- | :--- |
| **NIST FIPS 203 (ML-KEM-768)** | **Module-Lattice Key Encapsulation Mechanism.** Used to safely send secret encryption keys to individual recipients. | Protects against future quantum computers (*"Harvest Now, Decrypt Later"* attacks). Legacy RSA and ECC are excluded. |
| **AES-256-GCM** | **High-speed symmetric cipher.** Encrypts the raw document text using a random 256-bit Content Encryption Key (CEK). | Encrypting large documents with symmetric ciphers is fast and secure; the symmetric key is then protected by ML-KEM. |
| **NIST FIPS 204 (ML-DSA-65)** | **Module-Lattice Digital Signature Algorithm.** Used by recipients to sign a digital receipt before viewing the plaintext. | Proves **non-repudiation**: the recipient cannot mathematically deny that they opened and decrypted the file. |
| **SHA-256 Hashes** | **A mathematical fingerprint of any data.** | If a single letter or bit changes, the hash changes completely. Proves integrity of documents, packages, and ledger blocks. |
| **Zero-Width Forensic Watermark** | **Invisible Unicode characters inserted into whitespace.** Contains session ID, recipient ID, timestamp, and a CRC-16 checksum. | Invisible to human eyes ($SSIM \ge 0.9998$). If the document is copied or leaked, this hidden payload remains embedded in the text. |
| **Air-Gapped Distributed Ledger (DLT)** | **A local, permissioned blockchain** running with a 3/3 validator node quorum (Alpha, Bravo, Gamma). | Ensures access logs cannot be deleted or secretly edited, even by a rogue system administrator. |

---

## 2. Starting the Application

### GitHub Repository
Project source code: **[https://github.com/manoj-9899/sih](https://github.com/manoj-9899/sih)**

### Prerequisites
Make sure Node.js (version 18+ or 20+) and Git are installed on your computer.

### Step-by-Step Terminal Commands
1. Clone the repository and navigate into the project directory:
   ```bash
   git clone https://github.com/manoj-9899/sih.git
   cd sih
   ```
2. Install the project dependencies:
   ```bash
   npm install
   ```
3. Copy the sample environment file (no external API keys or cloud accounts needed):
   ```bash
   cp .env.example .env
   ```
4. Start the local development server:
   ```bash
   npm run dev
   ```
5. Open your browser and go to:
   ```text
   http://localhost:3000
   ```

You will see the dark-themed institutional workstation interface.

---

## 3. Understanding the Application Interface

### The Top Navigation Bar
* **Branding:** Displays *Post-Quantum Cryptographic Provenance Workstation (Air-Gapped DLT)*.
* **Telemetry Sub-bar:** Shows the live status of the local enclave, post-quantum engine (`FIPS 203 / 204`), and consensus quorum (`3/3 QUORUM`).
* **Operational Mode Switcher (Top Right):**
  * `[WORKSTATION]`: Clean, high-density, professional defense terminal with minimal text and no educational clutter.
  * `[GUIDED MODE]`: Activates inline collapsible guide panels, step-by-step instructions, and recommended actions on each screen.
* **Module Tabs:**
  1. **Mission Demo:** Automated, one-click walkthrough demonstrating the full pipeline.
  2. **Sender Studio:** Packaging and encrypting documents for multiple recipients.
  3. **Recipient Portal:** Decrypting documents, signing provenance events, and viewing watermarked plaintext.
  4. **Forensic Studio:** Ingesting leaked text, blind watermark extraction, and attribution.
  5. **DLT Explorer:** Inspecting blockchain blocks, Merkle trees, and running anti-tamper audits.
  6. **PQC Registry:** Directory of enrolled personnel keys and live key generation.
  7. **Attack Lab:** Negative security test bench running 7 automated adversarial attack simulations.

---

## 4. Step-by-Step Practical Walkthrough

### Step 1 — Start the System and Understand the Mode Switch

#### What to do:
1. Open `http://localhost:3000`.
2. Look at the top-right corner of the navigation bar.
3. Click `GUIDED MODE` if you want step-by-step guidance panels, or `WORKSTATION` for a clean, data-dense view.

#### What you should see:
* In **Guided Mode**, a cyan guidance card appears at the top of each tab explaining what to do.
* In **Workstation Mode**, guidance cards collapse away, presenting a streamlined operations console.

#### What is happening internally:
The app initializes in-memory post-quantum keypairs for 4 simulated defense personas (Alice, Bob, Charlie, Diana) using the `@noble/post-quantum` library and loads the genesis block of the local air-gapped ledger in browser IndexedDB.

#### Why this matters:
Allows both first-time evaluators (who want guided explanations) and security operators (who want a clean tool) to use the exact same workstation.

---

### Step 2 — Open Sender Studio & Review Available Documents

#### What to do:
Click the **Sender Studio** tab in the navigation bar.

#### What you should see:
* On the left: **1. Classified Document Dossier** listing registered classified intelligence files:
  * `DOC-2026-AEGIS-991` (*OPERATION AEGIS*, TOP SECRET // SCI)
  * `DOC-2026-QUANTUM-GRID-442` (*CRITICAL INFRASTRUCTURE*, SECRET)
  * `DOC-2026-MARITIME-SEC7` (*MARITIME PROTOCOL*, CONFIDENTIAL)
* On the right: Document content preview showing the raw classified text.

#### What is happening internally:
The system retrieves pre-stored intelligence dossiers from memory/IndexedDB. Each document has a cryptographic SHA-256 fingerprint computed from its plaintext bytes.

#### Why this matters:
Simulates a real command center environment where classified documents of various sensitivity levels are staged for distribution.

---

### Step 3 — Ingest or Create a Custom Document (Optional)

#### What to do:
1. Click the **Ingest Document** button in the top right of the Sender Studio.
2. In the modal, enter a custom title (e.g., `Operation Falcon Eye`), select classification (`TOP SECRET // SCI`), and paste or type custom text.
3. Click **Save & Ingest Dossier**.

#### What you should see:
The new document is added to the top of the dossier list and automatically selected.

#### What is happening internally:
The document is encoded into UTF-8 bytes and assigned an internal identifier (`DOC-CUSTOM-...`).

#### Why this matters:
Proves the system is not hardcoded to sample data—evaluators can test with any arbitrary text or real document file.

---

### Step 4 — Select Authorized Recipients

#### What to do:
1. In Sender Studio, scroll down to **2. Authorized Recipient Enclave Roster**.
2. Check the boxes for **Dr. Alice Vance** and **Col. Bob Martinez**.
3. **Leave Cmdr. Charlie Chen UNCHECKED.**

#### What you should see:
* Dr. Alice Vance: Checked (`[✓]`)
* Col. Bob Martinez: Checked (`[✓]`)
* Cmdr. Charlie Chen: Unchecked (`[ ]`)
* The summary line displays: `2 of 4 Recipients Authorized`.

#### What is happening internally:
The application queues the public keys (`ML-KEM-768`) of Alice and Bob for envelope encapsulation. Charlie's public key will not receive a key envelope.

#### Why this matters:
Demonstrates role-based broadcast encryption. Only authorized parties will have their keys encapsulated into the distribution package.

---

### Step 5 — Create the Encrypted Broadcast Package

#### What to do:
Click the primary button: **GENERATE ENCRYPTED PACKAGE** (or **Encrypt & Dispatch Multi-Recipient Package**).

#### What you should see:
* The button briefly displays `COMPUTING KEM ENVELOPES...` (or `PACKAGING...`).
* A green status banner appears: `PACKAGE GENERATED & BROADCAST DISPATCHED`.
* Section **3. Encrypted Broadcast Output Container** appears at the bottom with details for the generated package.

#### What is happening internally:
1. The engine generates a single, cryptographically random 256-bit symmetric Content Encryption Key (CEK).
2. The entire document body is encrypted once using **AES-256-GCM** with a fresh 96-bit random Initialization Vector (IV).
3. For Alice, the engine encapsulates the CEK using Alice's **ML-KEM-768** public key, producing an envelope containing a 1,088-byte KEM ciphertext.
4. For Bob, the engine encapsulates the same CEK using Bob's **ML-KEM-768** public key.
5. All envelopes and the single encrypted document payload are bundled into one package file (`.sihpkg`).

#### Why this matters:
**Broadcast Encryption Efficiency:** The document is encrypted **once**, not duplicated multiple times. Each recipient receives only their lightweight key envelope.

---

### Step 6 — Inspect and Understand the Package Structure

#### What to do:
1. Under **3. Encrypted Broadcast Output Container**, click **Inspect Raw Payload**.
2. Click **Download .sihpkg** to save the package locally if desired.

#### What you should see:
* An expandable view showing the JSON package structure:
  * `packageId`: e.g., `PKG-2026-...`
  * `ciphertextBase64`: AES-256 encrypted document bytes.
  * `ivHex` & `tagHex`: AES-GCM authentication parameters.
  * `envelopes`: Exactly two envelope items (Alice and Bob). Notice Charlie is completely absent.

#### What is happening internally:
The package is saved to local air-gapped storage (IndexedDB) as the active package across the workstation.

#### Why this matters:
An interceptor or unauthorized user seeing this package cannot decrypt the content because they lack a corresponding ML-KEM private key.

---

### Step 7 — Open Recipient Portal & Select an Operator Identity

#### What to do:
1. Click the **Recipient Portal** tab in the top navigation bar.
2. In the **Operator Credential Register**, click on **Dr. Alice Vance**.

#### What you should see:
* Alice's card is highlighted with a green badge: `ENVELOPE CLEARED: AUTHORIZED FOR DECRYPTION`.
* The big action button reads: **DECRYPT & BIND PROVENANCE EVENT**.

#### What is happening internally:
The portal scans the active package's `envelopes` array for Alice's recipient ID (`USR-ALICE-VANCE-01`). Finding a match, the access gate unlocks.

#### Why this matters:
Confirms that the hardware identity matches an authorized recipient in the broadcast container.

---

### Step 8 — Test Unauthorized Access (Negative Security Gate)

#### What to do:
In the **Operator Credential Register**, click on **Cmdr. Charlie Chen**.

#### What you should see:
* A red/amber indicator appears: `NO ENVELOPE` / `ACCESS REJECTED`.
* The decryption button is disabled with the label: `ACCESS REJECTED (NO ENVELOPE)`.
* An alert warns that Charlie has no encapsulated key in this package.

#### What is happening internally:
Charlie's ID is not present in the package envelopes. Because Charlie has no key envelope, he has no mathematical way to recover the Content Encryption Key (CEK).

#### Why this matters:
**Empirical Security Proof:** Demonstrates that unauthorized individuals cannot access the file even if they possess the encrypted broadcast package.

---

### Step 9 — Decrypt Document as an Authorized Recipient

#### What to do:
1. Switch back to **Dr. Alice Vance**.
2. Click the primary button: **DECRYPT & BIND PROVENANCE EVENT**.

#### What you should see:
Watch the 6-stage operational pipeline run:
* `01 ACCESS GATE` — Envelope cleared.
* `02 ML-KEM-768` — CEK decapsulated from Alice's envelope.
* `03 AES-256-GCM` — Document plaintext recovered.
* `04 STEGO BIND` — Unique session watermark injected.
* `05 ML-DSA-65` — Recipient hardware signs the decryption receipt.
* `06 DLT ANCHOR` — Event committed to the blockchain.
* Alice's decrypted document appears in the **Secure Document Viewport**.

#### What is happening internally:
1. Alice's private `ML-KEM-768` key decapsulates the shared secret from her envelope.
2. The recovered symmetric key decrypts the AES-256-GCM ciphertext in memory.
3. A unique 32-byte watermark payload is generated specifically for Alice's session.
4. Alice's private `ML-DSA-65` key signs an RFC 8785 canonical JSON summary of the event.
5. The signed transaction is sent to the local blockchain mempool and ratified by the 3/3 validator quorum into a new block.

#### Why this matters:
**Atomic Sign-Before-Release Guarantee:** The system refuses to release the plaintext until the digital signature is registered on the immutable ledger and the watermark is embedded.

---

### Step 10 — Understand Dynamic Watermarking and the Provenance Signature

#### What is happening under the hood:
* **The Watermark:** A 32-byte binary payload containing:
  * `0xA55A` (16-bit sync word)
  * `16-byte Session UUID`
  * `8-byte Recipient Fingerprint`
  * `4-byte Timestamp`
  * `2-byte CRC-16 Checksum`
  This binary payload is converted into invisible zero-width Unicode characters (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`) and woven into whitespace between sentences and words.
* **The Signature:** An authentic NIST FIPS 204 **ML-DSA-65** signature (3,309 bytes) over the canonical JSON record of the event.

#### Why this matters:
If Alice leaks this text, she cannot claim *"I never opened this document"* or *"Someone altered the database"* because her private key signed the transaction before she ever saw the plaintext.

---

### Step 11 — View Plaintext & Inspect the Invisible Forensic Channel

#### What to do:
1. Read the document in the **Secure Document Viewport**.
2. Click the **Inspect Forensic Channel** button.

#### What you should see:
* In normal view: Clean, standard plaintext with no visual blemishes or strange symbols ($SSIM \ge 0.9998$).
* When clicking **Inspect Forensic Channel**: Hidden zero-width characters light up with muted ochre markers, revealing the exact locations of the embedded steganographic bits. Click again to turn off.

#### What is happening internally:
The viewport temporarily highlights the invisible Unicode characters without altering the underlying text.

#### Why this matters:
Proves that the watermark is completely invisible to human readers while remaining mathematically extractable by machine algorithms.

---

### Step 12 — Simulate a Document Leak

#### What to do:
At the bottom of Alice's decrypted document viewport, click **Simulate Leak of Dr. Alice Vance's Copy** (or copy the text to your clipboard).

#### What you should see:
* A brief notification confirms the watermarked text has been copied.
* The application automatically switches you directly to the **Forensic Studio** with Alice's watermarked text pre-loaded in the ingestion box.

#### What is happening internally:
The exact watermarked text from Alice's viewport (including the invisible Unicode characters) is transferred to the forensic analysis input.

#### Why this matters:
Simulates a real-world intelligence leak where an authorized recipient copies sensitive text and pastes it outside the secure enclave (e.g., on a forum, via email, or to a journalist).

---

### Step 13 — Open Forensic Studio & Ingest the Leaked Artifact

#### What to do:
You are now in the **Forensic Studio** (if not, click **Forensic Studio** in the navbar). Verify that the leaked text is present in the **Leaked Artifact Ingestion** textarea.

#### What you should see:
* The text appears normal in the box.
* Above the box, a red indicator reads: `SIMULATED LEAK TARGET` (if redirected from the leak button).

#### What is happening internally:
The studio is ready to perform **blind extraction**—it does not need the original unwatermarked document or any secret keys to extract the watermark payload.

#### Why this matters:
Investigators rarely possess the original unedited file; blind extraction works on the leaked text alone.

---

### Step 14 — Execute Blind Forensic Attribution

#### What to do:
Click the large button: **EXECUTE BLIND FORENSIC ATTRIBUTION**.

#### What you should see:
* The button pulses with `EXTRACTING...`.
* The right panel displays the **Forensic Attribution Certificate**.
* A bold banner appears: `LEAK SOURCE ATTRIBUTED: DR. ALICE VANCE` with `CONFIDENCE SCORE: 100%`.

#### What is happening internally:
1. The forensic parser filters the text for the zero-width Unicode alphabet.
2. It detects the `0xA55A` synchronization word and decodes the 32-byte payload.
3. It validates the CRC-16 checksum to ensure no bits were corrupted.
4. It extracts the **Session UUID** and queries the local blockchain.
5. It locates the exact Decryption Event committed in Block #1.
6. It retrieves Alice's public `ML-DSA-65` key from the registry and verifies the 3,309-byte digital signature over the canonical JSON transaction.
7. All 4 checks pass, producing a 100% confidence verdict.

#### Why this matters:
**The Core Problem Solved:** Out of all recipients who received the document, the system has mathematically and indisputably identified that this specific leaked text came from **Dr. Alice Vance**.

---

### Step 15 — Verify the Cryptographic Evidence Chain

#### What to do:
Scroll down the Forensic Attribution Certificate on the right side of the screen.

#### What you should see:
A 4-step verified audit checklist:
1. `[✓] Steganographic Carrier Detection` — Sync header `0xA55A` verified.
2. `[✓] CRC-16 Checksum Integrity` — Payload uncorrupted.
3. `[✓] Ledger Provenance Correlation` — Matched to committed Block height.
4. `[✓] Post-Quantum Signature Verification` — Recipient's ML-DSA-65 signature valid.

Click **Inspect Cryptographic Proof** to view the full Base64 signature and Merkle inclusion proof.

#### What is happening internally:
The certificate displays the step-by-step mathematical proof chain required by defense standards.

#### Why this matters:
Provides an auditable evidentiary trail suitable for formal legal and national security proceedings.

---

### Step 16 — Download Court-Ready Attribution Certificate

#### What to do:
Click **Download Certificate (.json)** in the Forensic Studio.

#### What you should see:
A JSON file (e.g., `forensic_certificate_REP-....json`) downloads to your computer.

#### What is happening internally:
The system packages the report ID, session UUID, recipient profile, timestamp, block height, block hash, and cryptographic signature into a standardized JSON certificate.

#### Why this matters:
Allows forensic reports to be archived, exported, and presented in court or court-martial proceedings without requiring access to the live software.

---

### Step 17 — Inspect the Immutable Ledger in DLT Explorer

#### What to do:
Click the **DLT Explorer** tab in the top navigation bar.

#### What you should see:
* **Validator Quorum Status:** `3/3 Online` (Alpha, Bravo, Gamma nodes).
* **Chain Height:** Showing Block #0 (Genesis Block) and Block #1 (Alice's Decryption Event).
* Block details: Previous Block Hash, Current Block Hash, Binary Merkle Root, and Validator Signatures.

#### What is happening internally:
The DLT Explorer reads the local blockchain from IndexedDB. Each block contains a SHA-256 link to the preceding block and a Merkle tree root of all transactions.

#### Why this matters:
Provides total transparency into all decryption events across the organization.

---

### Step 18 — Simulate and Catch a Rogue Administrator Database Tamper

#### What to do:
1. In DLT Explorer, click **Audit Entire Chain**.
   - Result: `LEDGER INTEGRITY VERIFIED: 100% UNTAMPERED`.
2. Click the red button: **Simulate Rogue Admin Tamper**.
3. Observe what happens.
4. Click **Restore Quorum Integrity**.

#### What you should see:
* After clicking Simulate Tamper: A critical red alert sounds: `CRITICAL: BLOCKCHAIN TAMPERING DETECTED`.
* The audit engine flags the exact block (`Block #1`) and field that was altered.
* Clicking **Restore Quorum Integrity** repairs the chain and returns it to `100% UNTAMPERED`.

#### What is happening internally:
When you click Simulate Tamper, the app simulates a corrupt database admin modifying a historical transaction. When the auditor runs, the SHA-256 hash of Block #1 no longer matches the Merkle root and the previous hash stored in Block #2. The audit engine immediately catches the anomaly.

#### Why this matters:
**Anti-Tampering Guarantee:** Proves that even privileged database administrators cannot secretly erase an access log or frame someone else without breaking the cryptographic chain.

---

### Step 19 — Inspect Post-Quantum Keys in PQC Registry

#### What to do:
1. Click the **PQC Registry** tab.
2. Click on different personnel names (Alice, Bob, Charlie, Diana) to view their key fingerprints.
3. Click the button: **SYNTHESIZE LIVE PQC KEYPAIR**.

#### What you should see:
* The synthesizer runs in ~100–300 ms and generates an authentic, brand new `ML-KEM-768` (1,184-byte public key) and `ML-DSA-65` (1,952-byte public key) pair in memory.
* Monospace hex chips and a key fingerprint appear with 1-click copy buttons.

#### What is happening internally:
The app executes pure lattice-based polynomial mathematics via WebAssembly using `@noble/post-quantum`.

#### Why this matters:
Demonstrates that modern post-quantum cryptography runs smoothly and efficiently inside a standard client browser without requiring special supercomputers.

---

### Step 20 — Run Adversarial Tests in Attack Lab

#### What to do:
1. Click the **Attack Lab** tab.
2. Click **RUN ALL 7 SECURITY TESTS**.

#### What you should see:
All 7 adversarial tests execute sequentially with live progress spinners and finish with green `PASSED` badges:
1. `SEC-01`: Unauthorized Decryption Defense (No Envelope) — **PASSED**
2. `SEC-02`: Cross-Recipient Key Encapsulation Isolation — **PASSED**
3. `SEC-03`: Ciphertext Integrity & Bit-Flip Resistance (AES-GCM Auth Tag) — **PASSED**
4. `SEC-04`: Forged Recipient Signature Rejection (ML-DSA-65 Mempool Gate) — **PASSED**
5. `SEC-05`: Historical Ledger Tamper Detection (Merkle Tree Hash Break) — **PASSED**
6. `SEC-06`: False-Positive Watermark Extraction Protection — **PASSED**
7. `SEC-07`: Bit-Level Watermark Corruption Resilience — **PASSED**

#### What is happening internally:
The test harness runs automated negative security simulations, attempting to decrypt without keys, flip bits in ciphertexts, forge signatures, and inject tampered blocks. In every case, the cryptographic checks intercept and neutralize the attack.

#### Why this matters:
Proves the system's defenses empirically against real threat models.

---

## 5. Full Demo Scenario

Here is an end-to-end operational scenario you can follow and explain to an audience:

```text
[SCENARIO: THE CLASSIFIED RADAR SPECIFICATION LEAK]

1. SENDER:
   Command HQ packages "OPERATION AEGIS: Strategic Anti-Air Grid Protocol"
   Authorized Recipients:
   - Dr. Alice Vance (Naval Intelligence)
   - Col. Bob Martinez (Strategic Support Command)
   - [Cmdr. Charlie Chen is EXCLUDED]

2. ENCRYPTION:
   - AES-256-GCM encrypts document body with a random symmetric CEK.
   - CEK is wrapped for Alice with her ML-KEM-768 public key.
   - CEK is wrapped for Bob with his ML-KEM-768 public key.
   - Broadcast package (.sihpkg) is generated.

3. UNAUTHORIZED CHECK:
   - Charlie Chen attempts to decrypt the package in Recipient Portal.
   - ACCESS REJECTED: Charlie has no key envelope. Plaintext remains locked.

4. DECRYPTION (BOB):
   - Col. Bob Martinez logs into Recipient Portal.
   - Decapsulates his key envelope using ML-KEM-768.
   - Document body is decrypted in memory.
   - Invisible session watermark containing Bob's fingerprint is embedded.
   - Bob signs the Decryption Event with his ML-DSA-65 private key.
   - Transaction is committed to Block #1 on the air-gapped blockchain.
   - Plaintext is released to Bob's screen.

5. THE LEAK:
   - Bob leaks his copy of the document (copies text and sends it to the public).

6. FORENSIC INVESTIGATION:
   - Military intelligence recovers the leaked text and pastes it into Forensic Studio.
   - Blind extraction recovers the 32-byte payload and Session UUID.
   - Ledger lookup finds the Decryption Event in Block #1.
   - Recipient signature is verified against Bob's registered ML-DSA-65 public key.
   - VERDICT: 100% Mathematical Certainty — Col. Bob Martinez is the source.
```

---

## 5.1 Phase 6: Manual Forensic Demo Procedure (PDF Attribution)

Follow this 10-step evaluation procedure to test the complete forensic investigation pipeline across multiple recipients:

### Step 1: Alice Decrypts a PDF
1. Navigate to **Decrypt**.
2. Select **Dr. Alice Vance** from the operator dropdown.
3. Enter passphrase `AliceVance2026!` and click **Unlock Keystore**.
4. Click **Execute authenticated decryption**.
- **Expected UI Result:** Decryption completes; progress indicates ML-KEM-768 decapsulation, AES-256-GCM plaintext recovery, forensic watermark injection into `/ForensicProvenance`, and ML-DSA-65 signature commitment to a new ledger block.

### Step 2: Download Alice's Watermarked PDF
1. Click the **Download copy** button in Decrypt.
2. Save the file (e.g., `Joint_Defense_Plan_2026_Decrypted_AV.pdf`).
- **Expected UI Result:** Browser downloads a genuine PDF binary containing the structural watermark enclave.

### Step 3: Bob Decrypts the Same Source PDF
1. In **Decrypt**, select **Col. Bob Martinez**.
2. Enter passphrase `BobMartinez2026!` and click **Unlock Keystore**.
3. Click **Execute authenticated decryption**.
- **Expected UI Result:** Bob's separate session is established; a unique Session UUID and watermark ID are dynamically generated; a distinct ML-DSA-65 signature is committed to the next ledger block.

### Step 4: Download Bob's Watermarked PDF
1. Click **Download copy**.
2. Save the file (e.g., `Joint_Defense_Plan_2026_Decrypted_BM.pdf`).
- **Expected UI Result:** Browser downloads Bob's watermarked PDF binary.

### Step 5: Open Both Documents Side-by-Side
1. Open Alice's PDF and Bob's PDF in any standard PDF viewer (Preview, Acrobat, Chrome).
- **Expected UI Result:** Both documents display identical visual layout, margins, typography, page count, and content with zero human-perceptible distortion ($SSIM \ge 0.999$).

### Step 6: Confirm They Look the Same
1. Verify that no visible stamps, black bars, or discolored artifacts appear on either document.
- **Expected UI Result:** Human inspection cannot distinguish between Alice's and Bob's copies.

### Step 7: Upload Alice's PDF to Forensics
1. Navigate to **Forensics** (or click "Simulate anonymous leak" from Alice's session).
2. Drag and drop Alice's downloaded PDF into the upload area.
- **Expected UI Result:** Filename and file size (e.g., `Joint_Defense_Plan_2026_Decrypted_AV.pdf`, ~24.5 KB) are displayed with status: `PDF structure verified • Ready for blind structural analysis`.

### Step 8: Analyze
1. Click **Analyze document**.
- **Expected UI Result:** Live 5-stage progress indicator advances through PDF Validation, Enclave Extraction, CRC-16 Verification, Ledger Event Query, and ML-DSA-65 Signature Verification.

### Step 9: Show Alice's Verified Attribution
1. Review the result card on screen.
- **Expected UI Result:**
  - Status banner: **FORENSIC VERIFICATION COMPLETE** &bull; **VERIFIED**
  - Notice: *"Cryptographically verified decryption event associated with the registered recipient key."*
  - Recipient: **Dr. Alice Vance**
  - Decryption event: `EVT-...`
  - Forensic fingerprint: `WM-...`
  - Signature: `VALID (ML-DSA-65 • FIPS 204)`
  - Ledger evidence: `VERIFIED (Block #...)`
  - Evidence chain: All 5 checkmarks displayed green.
  - Click **View evidence** to inspect technical drawer with document SHA-256 hash, Merkle root, and block hashes.

### Step 10: Repeat with Bob
1. Click **Clear** in Forensics.
2. Upload Bob's PDF file (`Joint_Defense_Plan_2026_Decrypted_BM.pdf`).
3. Click **Analyze document**.
- **Expected UI Result:**
  - Recipient attributes specifically to **Col. Bob Martinez**.
  - Watermark ID, Session UUID, Decryption Event ID, and block height differ from Alice's investigation.
  - Verification status: **VERIFIED**.
  - Both investigations appear logged under **Investigation history** tab.

---

## 6. Troubleshooting Common Demo Issues

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **Decryption button is disabled** | The selected recipient was not checked when creating the package in Sender Studio. | Switch to a recipient who was checked (e.g., **Dr. Alice Vance**), or return to Sender Studio and create a new package with that recipient selected. |
| **Forensic Studio shows `FAILED_EXTRACTION`** | The pasted text does not contain invisible zero-width watermarks. | Make sure you copied the text from the **Recipient Portal** after decrypting, or use the **Simulate Leak** shortcut button. Plain raw text from Sender Studio has no watermark. |
| **DLT Explorer shows red tampering alert** | You clicked **Simulate Rogue Admin Tamper**. | Click the green **Restore Quorum Integrity** button to repair the blockchain state. |
| **Port 3000 is busy** | Another process is using port 3000. | Run `npm run dev -- --port 3001` to start on an alternative port. |
| **Browser IndexedDB seems out of sync** | Multiple browser tabs or old state in storage. | Refresh the browser tab or click **Reset** on the Mission Demo tab to reset local state. |

---

## 7. What You Should Understand After Completing the Demo

By completing this walkthrough, you have seen:

1. **How broadcast encryption works in post-quantum defense:** Large documents are encrypted once with symmetric AES-256-GCM, and the symmetric key is wrapped individually for each recipient using NIST FIPS 203 (ML-KEM-768).
2. **Why sign-before-release is essential:** Requiring an authentic NIST FIPS 204 (ML-DSA-65) digital signature before plaintext display guarantees non-repudiation.
3. **How imperceptible steganography prevents deniability:** Embedding session-specific zero-width characters into whitespace creates an invisible forensic trail without affecting readability.
4. **Why an immutable distributed ledger is necessary:** Storing decryption receipts in an air-gapped blockchain with Merkle trees prevents administrators or adversaries from altering audit records.
5. **How blind forensic attribution operates:** Leaked texts can be tied back to their exact recipient and decryption session with 100% mathematical certainty.
