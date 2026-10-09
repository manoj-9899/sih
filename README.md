# SIH26237: Post-Quantum Document Enclave & Forensic Attribution System

> **Repository:** [https://github.com/manoj-9899/sih-26237](https://github.com/manoj-9899/sih-26237)  
> **One-Line Description:** A quantum-safe, multi-recipient document distribution workstation that embeds invisible forensic watermarks at decryption time and anchors non-repudiable post-quantum provenance signatures into an offline immutable distributed ledger.  
> **SIH Problem Statement ID:** SIH26237  
> **Project Status:** Complete Functional Prototype / Browser-Based Air-Gapped Cryptographic Enclave  

---

## 1. What Is This Project?

Imagine a military commander or corporate director who needs to send a classified strategy document to three people: **Alice**, **Bob**, and **Charlie**.

With standard encryption (like traditional PGP, email encryption, or password-protected PDFs):
1. The sender encrypts the document.
2. All three recipients decrypt it and receive the **exact same text or file**.
3. If someone leaks that document to a reporter or posts it on the internet, **all three copies look identical**. There is no mathematical or forensic way to prove who leaked it. Everyone can deny responsibility, saying *"Someone else must have leaked it."*

**This project solves that exact problem.**

Instead of simply handing out decrypted text, this workstation binds **decryption to an accountable cryptographic event**:
* When a recipient opens and decrypts the document, the software silently weaves an **invisible watermark** into the text containing their unique identity, session ID, and timestamp.
* Before showing the plaintext document, the system requires the recipient's post-quantum digital signature and records the event in an **immutable, air-gapped distributed ledger (DLT)**.
* If a recipient leaks the document, an investigator can feed the leaked text into the **Forensic Studio**. The software extracts the hidden watermark, checks the blockchain ledger, verifies the digital signature, and proves exactly who leaked the document with mathematical certainty.

---

## 2. What Does This Project Do?

The application provides a complete, end-to-end lifecycle for classified document distribution:

```text
Classified Document
        ↓
Broadcast Encryption (Encrypted once with AES-256-GCM)
        ↓
Multi-Recipient Key Envelopes (Individually encapsulated with ML-KEM-768)
        ↓
Recipient Decryption Verification (Clearance checked, envelope decapsulated)
        ↓
Invisible Forensic Watermarking (Unique session & recipient ID injected)
        ↓
Post-Quantum Digital Signing (Recipient signs event with ML-DSA-65)
        ↓
Offline Distributed Ledger (Transaction committed to local blockchain block)
        ↓
Plaintext Release (Recipient reads customized, clean document)
        ↓
[Document is Leaked]
        ↓
Forensic Studio Ingestion (Blind steganographic extraction)
        ↓
Ledger Record Match & Signature Audit
        ↓
Indisputable Attribution Result (Perpetrator Identified)
```

```

---

## 3. Dual Operational Modes (Workstation Mode vs. Guided Mode)

The interface includes a top navigation toggle switch tailored for both defense operators and first-time evaluators:

* **`[WORKSTATION]` (Clean / Professional):**
  A high-density, status-first security terminal. Strips away educational text and paragraphs, prioritizing quick scanning, operational badges, concise telemetry bars, and one-click actions. Advanced cryptographic proofs (Merkle branches, raw hex keys, and base64 signatures) are accessed cleanly via on-demand drawers.
* **`[GUIDED MODE]` (Beginner / Evaluator):**
  Provides inline, collapsible guidance panels on every screen. Clearly explains *what is happening*, *the recommended next action*, and *what cryptographic proofs to observe*. It features quick-action buttons to guide you seamlessly through the entire demonstration without reading the source code.

---

## 4. Quick Start / Beginner Walkthrough

You can set up, run, and demonstrate this entire application on your computer in less than 5 minutes.

### Step 1: Check Prerequisites
Make sure you have Node.js and Git installed on your computer:
* **Node.js**: Version 18.0.0 or higher (Node 20+ recommended). Check by opening your terminal and typing:
  ```bash
  node -v
  ```
* **npm**: Version 9.0.0 or higher. Check with:
  ```bash
  npm -v
  ```
* **Git**: Check with:
  ```bash
  git --version
  ```

### Step 2: Clone the Repository
Open your terminal (Command Prompt, PowerShell, or macOS/Linux Terminal) and run:
```bash
git clone https://github.com/manoj-9899/sih-26237.git
cd sih-26237
```

### Step 3: Install Dependencies
Install the required packages using npm:
```bash
npm install
```

### Step 4: Configure Environment Variables (Optional)
Copy the sample environment configuration file (no external API keys or cloud accounts are needed for local operation):
```bash
cp .env.example .env
```

### Step 5: Start the Local Development Server
Start the local development server:
```bash
npm run dev
```

### Step 6: Open the Application
Open your web browser and navigate to:
```text
http://localhost:3000
```
You will immediately see the Post-Quantum Cryptographic Provenance Workstation interface.

---

### Step-by-Step Demonstration Script (Try This in the Browser!)

Follow these exact steps in the running app to see the entire cryptographic pipeline in action:

#### 1. Create and Encrypt a Package in Sender Studio
1. Click the **Sender Studio** tab in the top navigation bar.
2. In the **Classified Document Archive**, select `DOC-2026-AEGIS-991` (*OPERATION AEGIS*).
3. Under **Authorized Recipient Enclave Roster**, check **Dr. Alice Vance** and **Col. Bob Martinez**, but leave **Charlie Chen** unchecked.
4. Click the large button: **Encrypt & Dispatch Multi-Recipient Package**.
5. **What you see:** A single encrypted package is created. You will see individual NIST FIPS 203 (ML-KEM-768) key envelopes generated for Alice and Bob.

#### 2. Decrypt as an Authorized Recipient
1. Click the **Recipient Portal** tab.
2. In the **Operator Credential Register**, click on **Dr. Alice Vance**.
3. Notice the green badge: `ENVELOPE CLEARED: AUTHORIZED FOR DECRYPTION`.
4. Click **DECRYPT & BIND PROVENANCE EVENT**.
5. **What you see:** Watch the 6-stage operational pipeline run:
   * `01 GATE` (Enclave clearance verified)
   * `02 KEM` (ML-KEM-768 decapsulates the key)
   * `03 AES` (AES-256-GCM decrypts the document)
   * `04 STEGO` (Invisible watermark is injected)
   * `05 DSA` (ML-DSA-65 signs the provenance event)
   * `06 DLT` (Event is anchored into the ledger)
6. Alice's clean, decrypted document appears in the **Secure Document Viewport**.
7. Click **Inspect Forensic Channel** to view the hidden session identifier embedded in Alice's document without modifying the reading text. Click it again to close.

#### 3. Test Unauthorized Access
1. In the **Recipient Portal**, switch the active persona to **Charlie Chen**.
2. **What you see:** A red alert appears: `ACCESS REJECTED (NO ENVELOPE)`. Because Charlie was not selected by the sender, he cannot decapsulate the document key, and the decryption button is completely disabled.

#### 4. Simulate a Document Leak
1. Switch back to **Dr. Alice Vance** in the Recipient Portal.
2. Scroll to the bottom of Alice's document and click **Simulate Leak of Dr. Alice Vance's Copy**.
3. **What happens:** The application automatically copies Alice's uniquely watermarked text and switches directly to the **Forensic Studio**.

#### 5. Catch the Leaker in Forensic Studio
1. You are now in the **Forensic Studio** with the leaked text pre-loaded in the ingestion box.
2. Click **EXECUTE BLIND FORENSIC ATTRIBUTION**.
3. **What you see:** The forensic engine scans the zero-width whitespace entropy, extracts the 32-byte binary payload, queries the ledger, matches the watermark commitment in Block #1, verifies Alice's ML-DSA-65 signature, and generates the **Forensic Attribution Certificate** naming **Dr. Alice Vance** as the leaker with 100% mathematical certainty.
4. Click **Download Certificate (.json)** to export the court-ready proof.

#### 6. Audit the Immutable Ledger in DLT Explorer
1. Click the **DLT Explorer** tab.
2. Inspect the **Committed Blocks Rail** to view Block #1 and its Merkle root.
3. Click **Audit Entire Chain**. Notice the result: `LEDGER INTEGRITY VERIFIED: 100% UNTAMPERED`.
4. Click **Simulate Rogue Admin Tamper**. A rogue database administrator attempts to modify a historical record.
5. The audit engine immediately sounds a critical alert, pinpointing the exact block height and hash mismatch where tampering occurred.
6. Click **Restore Quorum Integrity** to return the ledger to a synchronized state.

#### 7. Run Security Tests in Attack Lab
1. Click the **Attack Lab** tab.
2. Click **RUN ALL 7 SECURITY TESTS**.
3. Watch the automated suite execute real cryptographic attacks against the codebase (ciphertext bit-flips, fake signature injections, cross-recipient key mismatches) and verify that all defenses pass.

---

## 4. Key Features

* **Broadcast Multi-Recipient Encryption (ML-KEM-768):**
  Encrypts the document payload once using AES-256-GCM and wraps the 256-bit Content Encryption Key (CEK) independently for each recipient using NIST FIPS 203 (ML-KEM-768). Legacy RSA and ECC are completely excluded.
* **Invisible Decryption-Time Watermarking:**
  Embeds a structured 32-byte binary payload (sync header, session UUID, watermark ID, recipient fingerprint, timestamp, and CRC-16 checksum) into zero-width Unicode whitespace characters. The text appears completely unaltered to human readers and word processors ($SSIM \ge 0.9998$, $PSNR > 49\text{ dB}$).
* **Post-Quantum Provenance Signatures (ML-DSA-65):**
  Uses NIST FIPS 204 (ML-DSA-65) digital signatures to sign RFC 8785 canonical JSON records of every decryption event before releasing plaintext.
* **Offline Air-Gapped Distributed Ledger (DLT):**
  A local permissioned blockchain operating in browser enclave storage with SHA-256 block hash chaining, binary Merkle tree DAG validation, and 3/3 validator quorum logic.
* **Administrative Anti-Tamper Auditor:**
  Detects unauthorized database modifications or retroactive administrator tampering down to the exact block, byte, and transaction hash.
* **Court-Ready Forensic Evidence Certificate:**
  Generates a deterministic verification chain mapping extracted payload data to immutable ledger blocks and exporting a signed JSON attribution certificate.
* **Automated Adversarial Security Suite (Attack Lab):**
  Features 7 empirical negative security stress tests validating that unauthorized users cannot decrypt documents, fake signatures cannot enter the mempool, and bit-flips are detected.

---

## 5. How the System Works (End-to-End Workflow)

```text
+-------------------------------------------------------------------------------+
| SENDER STUDIO                                                                 |
| 1. Selects classified document                                                |
| 2. Selects authorized recipients (e.g., Alice and Bob)                        |
| 3. Generates 256-bit symmetric key (CEK)                                      |
| 4. Encrypts document body with AES-256-GCM                                    |
| 5. Encapsulates CEK for Alice (ML-KEM-768) -> Envelope A                       |
| 6. Encapsulates CEK for Bob   (ML-KEM-768) -> Envelope B                       |
| 7. Packages ciphertext + envelopes into a single broadcast container          |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| RECIPIENT PORTAL (e.g., Alice)                                                |
| 1. Checks access gate: Is Alice's envelope present? (YES)                     |
| 2. Decapsulates CEK using Alice's private ML-KEM-768 key                      |
| 3. Decrypts ciphertext with AES-256-GCM -> Plaintext recovered                 |
| 4. Injects invisible 32-byte binary watermark into whitespace entropy         |
| 5. Signs Decryption Event using Alice's ML-DSA-65 private key                 |
| 6. Commits signed event to Air-Gapped DLT Mempool                             |
| 7. 3/3 Validator Quorum ratifies Block -> Transaction finalized               |
| 8. Clean, watermarked document released to Alice's viewport                   |
+-------------------------------------------------------------------------------+
                                      |
                           [Document is Leaked]
                                      v
+-------------------------------------------------------------------------------+
| FORENSIC STUDIO                                                               |
| 1. Ingests leaked document text or file                                       |
| 2. Blindly extracts zero-width whitespace character sequence                  |
| 3. Decodes 32-byte payload & verifies CRC-16 checksum                         |
| 4. Queries Air-Gapped DLT using extracted Session UUID                        |
| 5. Verifies ML-DSA-65 digital signature against recipient's public key        |
| 6. Confirms Merkle inclusion proof in committed block                         |
| 7. Issues definitive Forensic Attribution Certificate identifying the leaker  |
+-------------------------------------------------------------------------------+
```

---

## 6. Application Screens / Modules

The interface is built as a dark-mode institutional defense workstation:

| Screen | Purpose | Operator Actions |
| :--- | :--- | :--- |
| **Mission Demo** | Guided walkthrough | Step through an automated simulation showing sender encryption, dual recipient decryption, leak simulation, and forensic attribution. |
| **Sender Studio** | Packaging and dispatch terminal | Choose a classified document, toggle authorized recipients, trigger ML-KEM-768 broadcast encryption, inspect key envelopes, and dispatch the package. |
| **Recipient Portal** | Secure decryption workstation | Select an enrolled operator identity, verify envelope authorization, execute the 6-stage decryption pipeline, inspect the forensic stego channel (muted ochre), read the decrypted document, download `.txt`, or simulate a leak. |
| **Forensic Studio** | Forensic investigation workbench | Ingest a leaked document via text paste or file upload, execute blind stego extraction, query the DLT ledger, verify the ML-DSA-65 signature, and export a court-ready certificate (`.json`). |
| **DLT Explorer** | Offline ledger inspection console | Monitor the 3/3 validator quorum, inspect committed blocks and Merkle roots, audit full chain integrity, and simulate/restore rogue administrator database tampering attacks. |
| **PQC Registry** | Cryptographic identity directory | Inspect enrolled personnel public keys (ML-KEM-768 and ML-DSA-65), copy raw hex strings, view fingerprints, and synthesize live post-quantum keypairs via client WebAssembly. |
| **Attack Lab** | Adversarial security testing bench | Run 7 automated cryptographic stress tests (unauthorized access, ciphertext bit-flips, signature forgery, historical ledger rewrites, false positives) with live log streams. |

---

## 7. System Architecture

```text
+-------------------------------------------------------------------------------+
|                           USER PRESENTATION LAYER                             |
|      Mission Demo | Sender Studio | Recipient Portal | Forensic Studio        |
|      DLT Explorer | PQC Registry  | Attack Lab       | Navbar Navigation      |
+-------------------------------------------------------------------------------+
                                      |
+-------------------------------------------------------------------------------+
|                         APPLICATION SERVICES LAYER                            |
|                  DistributionService (Orchestrator Facade)                    |
+-------------------------------------------------------------------------------+
         |                           |                          |
         v                           v                          v
+------------------+       +------------------+       +------------------+
|   CRYPTOGRAPHY   |       |  STEGANOGRAPHY   |       |   LEDGER / DLT   |
| • ML-KEM-768     |       | • Zero-Width     |       | • Block Chaining |
| • ML-DSA-65     |       | • 32-Byte Payload|       | • Merkle Trees   |
| • AES-256-GCM    |       | • CRC-16 Check   |       | • 3/3 Quorum     |
| • PBKDF2 KDF     |       | • Invariance Calc|       | • Anti-Tamper    |
+------------------+       +------------------+       +------------------+
         \                           |                          /
          \                          |                         /
           +-------------------------v------------------------+
           |                 STORAGE ENCLAVE                  |
           | • IndexedDB (sih26237_airgap_store_v1)           |
           | • Encrypted Local Keystores                      |
           | • Ledger Block Store & Event Registry            |
           +--------------------------------------------------+
```

### Module Responsibilities:
* **`src/crypto/pqc.ts`:** Implements all cryptographic primitives using `@noble/post-quantum` and native Web Crypto APIs.
* **`src/watermark/engine.ts`:** Implements binary payload serialization, zero-width steganographic embedding, extraction, and image/text visual invariance calculations.
* **`src/ledger/dlt.ts`:** Implements the local permissioned blockchain, Merkle root calculations, validator quorum attestations, and full-chain verification.
* **`src/services/distributionService.ts`:** Connects the cryptographic, watermarking, and ledger layers into end-to-end workflows.
* **`src/storage/airGappedStorage.ts`:** Manages client-side persistence in IndexedDB without external network requests.

---

## 8. Cryptography and Security

All asymmetric cryptography in this project strictly adheres to finalized NIST Post-Quantum Cryptography standards:

| Cryptographic Primitive | Standard / Algorithm | Exact Parameter Set | Purpose in System |
| :--- | :--- | :--- | :--- |
| **Key Encapsulation (KEM)** | NIST FIPS 203 | `ML-KEM-768` (Kyber) | Encapsulates the symmetric Content Encryption Key (CEK) for each recipient. Public key: 1,184 bytes; Ciphertext: 1,088 bytes. |
| **Digital Signature (DSA)** | NIST FIPS 204 | `ML-DSA-65` (Dilithium) | Recipient signs the Decryption Event before plaintext release. Public key: 1,952 bytes; Signature: 3,309 bytes. |
| **Content Encryption** | NIST SP 800-38D | `AES-256-GCM` | Encrypts the raw document body using a 256-bit key, 96-bit random IV, and 128-bit authentication tag. |
| **Local Keystore Protection**| NIST SP 800-132 | `PBKDF2-HMAC-SHA256` | Derives keystore encryption keys using 100,000 iterations to protect private keys at rest. |
| **Hashing & Commitments** | FIPS 180-4 | `SHA-256` | Calculates document hashes, package hashes, watermark commitments, block hashes, and Merkle tree leaves. |

*Legacy asymmetric algorithms (RSA, ECDSA, ECDH) are completely excluded.*

---

## 9. Technology Stack

| Layer | Technology | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Frontend Framework** | React | `^19.0.1` | Single-page reactive user interface |
| **Language** | TypeScript | `^7.0.2` | Type safety across cryptographic and ledger models |
| **Bundler & Dev Server**| Vite | `^8.3.0` | Ultra-fast local development and production bundling |
| **Post-Quantum Crypto** | `@noble/post-quantum` | `^0.7.1` | Pure, audited TypeScript implementations of ML-KEM and ML-DSA |
| **Symmetric Crypto** | Web Cryptography API | Native | Standard AES-256-GCM encryption and PBKDF2 key derivation |
| **Styling** | Tailwind CSS | `^4.3.3` | Utility-first styling with custom defense workstation tokens |
| **Icons** | Lucide React | `^0.546.0` | Technical icons for buttons, status indicators, and tabs |
| **Animations** | Motion | `^12.23.24` | Smooth operational transitions |
| **Local Persistence** | IndexedDB | Native | Offline browser database for air-gapped record retention |

---

## 10. Project Structure

```text
SIH26237/
├── package.json                      # Dependency declarations & scripts
├── tsconfig.json                     # TypeScript compiler configuration
├── vite.config.ts                    # Vite build configuration
├── index.html                        # Application entry point HTML
├── .env.example                      # Sample environment configuration
├── src/
│   ├── App.tsx                       # Root routing & active tab state
│   ├── main.tsx                      # React DOM mounting entry point
│   ├── index.css                     # Global Tailwind styles & dark color tokens
│   ├── components/                   # Screen components & UI primitives
│   │   ├── Navbar.tsx                # Workstation top navigation bar
│   │   ├── WalkthroughTab.tsx        # Mission Demo interactive walkthrough
│   │   ├── SenderStudio.tsx          # Sender packaging and broadcast screen
│   │   ├── RecipientPortal.tsx       # Secure recipient decryption workstation
│   │   ├── ForensicStudio.tsx        # Blind extraction and attribution screen
│   │   ├── DltExplorer.tsx           # Blockchain inspector & anti-tamper auditor
│   │   ├── PqcRegistry.tsx           # Post-quantum personnel keystore registry
│   │   ├── SecurityTestHarness.tsx   # Attack Lab (7 adversarial stress tests)
│   │   └── ui/
│   │       └── WorkstationPrimitives.tsx # Reusable UI components (Buttons, Surfaces, Badges)
│   ├── crypto/
│   │   └── pqc.ts                    # ML-KEM-768, ML-DSA-65, AES-GCM, PBKDF2 logic
│   ├── data/
│   │   └── sampleData.ts             # Pre-configured documents, personas, and keys
│   ├── ledger/
│   │   └── dlt.ts                    # Blockchain, Merkle trees, quorum, and auditor logic
│   ├── services/
│   │   └── distributionService.ts    # Application facade orchestrating crypto + DLT + stego
│   ├── storage/
│   │   └── airGappedStorage.ts       # IndexedDB storage wrapper for offline operation
│   ├── types/
│   │   └── index.ts                  # Core TypeScript interfaces for packages, events, blocks
│   └── watermark/
│       └── engine.ts                 # Zero-width steganography, CRC-16, and SSIM metrics
```

---

## 11. Requirements

* **Operating System:** Windows 10/11, macOS, or Linux (Ubuntu, Debian, Fedora, Arch, etc.).
* **Node.js:** `v18.0.0` or higher (`v20.x` recommended).
* **npm:** `v9.0.0` or higher.
* **Modern Web Browser:** Google Chrome, Microsoft Edge, Brave, Mozilla Firefox, or Safari (supporting the Web Cryptography API and IndexedDB).
* **Network:** An internet connection is needed **only** during `npm install`. The application runs 100% offline at runtime.

---

## 12. Installation and Configuration

### 1. Clone the project
```bash
git clone <repository-url>
cd <repository-directory>
```

### 2. Install dependencies
```bash
npm install
```

### 3. Environment Configuration
The application runs entirely on client-side Web Cryptography and WebAssembly. No secret keys or remote database credentials are required. Create a local `.env` file from the example:
```bash
cp .env.example .env
```

The `.env.example` contents:
```env
# Optional environment variables
VITE_APP_TITLE=SIH26237 Defense Enclave
VITE_DEFAULT_LOCALE=en-US
```

---

## 13. Running the Project

### Development Server
To launch the interactive workstation:
```bash
npm run dev
```
Open your browser and navigate to:
```text
http://localhost:3000
```

### Production Build
To compile optimized static assets:
```bash
npm run build
```
The compiled files will be output to the `dist/` directory.

### Preview Production Build
To preview the compiled production build locally:
```bash
npm run preview
```

---

## 14. Testing and Code Verification

### 1. TypeScript Type Checking / Linting
Verify that all types, cryptographic interfaces, and components compile with zero errors:
```bash
npm run lint
```
*Behind the scenes, this executes `tsc --noEmit`.*

### 2. Production Build Compilation Check
Ensure the bundler compiles all assets cleanly:
```bash
npm run build
```

### 3. Adversarial Attack Lab (In-App Tests)
The application includes an automated security testing suite in the **Attack Lab** tab (`src/components/SecurityTestHarness.tsx`). Click **RUN ALL 7 SECURITY TESTS** to execute live attacks against browser memory:
* `SEC-01`: Rejection of unauthorized recipients lacking an ML-KEM envelope.
* `SEC-02`: Rejection of cross-recipient key decapsulation attempts.
* `SEC-03`: Rejection of ciphertext modified by single-bit flips (AES-GCM authentication tag failure).
* `SEC-04`: Rejection of forged digital signatures submitted to the DLT mempool.
* `SEC-05`: Detection of historical ledger block modifications via broken Merkle roots.
* `SEC-06`: Refusal to attribute unwatermarked documents (zero false-positives).
* `SEC-07`: Recovery of watermarks under minor whitespace transmission noise.

---

## 15. Security Model

### What the System Protects
1. **Confidentiality in Transit & Storage:** Documents are encrypted with AES-256-GCM. An adversary intercepting the package cannot decrypt the content without decapsulating an authorized ML-KEM-768 envelope.
2. **Post-Quantum Security:** Symmetric keys are protected by lattice-based cryptography (ML-KEM-768), safeguarding documents against *"Harvest Now, Decrypt Later"* attacks.
3. **Decryption Accountability:** A recipient cannot access the plaintext without triggering the injection of an invisible watermark and signing a Decryption Event.
4. **Non-Repudiation:** Once a recipient signs the Decryption Event with their ML-DSA-65 private key, they cannot mathematically deny having decrypted that document.
5. **Ledger Immutability:** Because each block references the previous block's SHA-256 hash and includes a binary Merkle tree root signed by a validator quorum, retroactive modification of access logs is immediately detected.

### Security Boundaries & Realistic Expectations
* **Plaintext Leak Protection:** No cryptographic system can physically prevent a user from reading authorized text on a monitor. Instead, this system provides **deterrence and accountability**: if the user copies, takes a screenshot of, or leaks the text, their identity is forensically extractable.
* **Keystore Protection:** Private keys are stored in encrypted form in the browser's local storage using PBKDF2 and AES-256-GCM. In an enterprise military deployment, this component would be backed by a physical hardware security token (FIPS 140-3 HSM or Smart Card).

---

## 16. Offline & Air-Gapped Operation

### Implemented Reality
* **Zero Remote Network Calls:** At runtime, the application makes no external API requests, loads no external fonts from CDNs, and contacts no cloud telemetry services.
* **Client-Side Cryptography:** All key generation, ML-KEM encapsulation/decapsulation, ML-DSA signing, AES-GCM encryption, and SHA-256 hashing run directly in the browser's local WebAssembly/JavaScript environment.
* **Local Persistence:** The blockchain, keystores, and distribution packages are stored locally in the browser's **IndexedDB** (`sih26237_airgap_store_v1`).
* **Airplane Mode Test:** You can disconnect your network cable or turn on Airplane Mode, and the entire workstation (packaging, decryption, signing, blockchain, and forensic attribution) will continue to operate normally.

---

## 17. Limitations & Prototype Boundaries

To maintain technical credibility and engineering honesty, the following constraints are documented:

1. **Simulated Hardware Keystores:** Private keys are protected using browser-level encryption (PBKDF2 + AES-GCM). While functional for a prototype, production defense deployments require physical smart cards, TPM 2.0, or PKCS#11 hardware security modules (HSMs).
2. **Document Formats:** The current steganographic engine is designed for **text-based classified intelligence documents** (`.txt`, `.md`). It injects zero-width whitespace permutations. It does not currently inject watermarks into binary image files, scanned PDFs, or physical printed paper.
3. **Watermark Robustness:** The watermark survives copy-pasting, document re-saving, and minor whitespace edits. However, extensive human paraphrasing (re-writing the document in different words) or optical character recognition (OCR) from low-resolution photographs will degrade or destroy the whitespace carrier.
4. **In-Enclave Distributed Ledger:** The 3-node validator quorum (Alpha, Bravo, Gamma nodes) runs within the client-side DLT service to allow complete demonstration on a single computer. In a production enterprise deployment, each validator would be an independent physical server on an isolated local network.

---

## 18. Troubleshooting

| Issue | Likely Cause | Solution |
| :--- | :--- | :--- |
| **`npm install` fails** | Incompatible Node.js version | Ensure you are running Node.js version 18.0.0 or higher (`node -v`). Update Node if needed. |
| **Port 3000 is in use** | Another application is running on port 3000 | Run `npm run dev -- --port 3001` or stop the application using port 3000. |
| **Decryption button is disabled** | The active recipient is not in the package envelope list | Switch to an authorized recipient (e.g., **Dr. Alice Vance**) who was selected during package creation in Sender Studio. |
| **Forensic Studio says `FAILED_EXTRACTION`** | Text pasted without watermarks | Ensure you copied the watermarked text from the Recipient Portal (or used the **Simulate Leak** button). Plain, unwatermarked text cannot be attributed. |
| **DLT Explorer shows `TAMPERING DETECTED`** | Simulated tamper attack was triggered | Click the green **Restore Quorum Integrity** button in DLT Explorer to return the ledger to a clean state. |

---

## 19. Security Disclaimer

This software is an engineering prototype developed for the **Smart India Hackathon (SIH26237)** to demonstrate the feasibility of combining post-quantum lattice cryptography, client-side decryption watermarking, and air-gapped distributed ledgers. 

While it utilizes mathematically authentic NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) algorithms from the audited `@noble/post-quantum` library, this implementation has not undergone independent third-party common criteria evaluation or military security certification. Do not use this software to store or distribute real, legally protected state secrets without deploying appropriate hardware security modules (HSMs) and certified physical infrastructure.

---

## 20. SIH26237 Requirement Mapping

| SIH26237 Requirement | Implementation in This Project | Source File / Module | Status |
| :--- | :--- | :--- | :--- |
| **Post-Quantum Cryptography** | NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) via `@noble/post-quantum`. | `src/crypto/pqc.ts` | **Implemented** |
| **Multi-Recipient Broadcast** | Broadcast AES-256-GCM encryption with individual recipient ML-KEM-768 key envelopes. | `src/services/distributionService.ts` | **Implemented** |
| **Decryption-Time Watermarking**| Dynamic zero-width whitespace steganography embedded during client plaintext recovery. | `src/watermark/engine.ts` | **Implemented** |
| **Non-Repudiation Provenance** | Recipient cryptographically signs Decryption Event using ML-DSA-65 before release. | `src/crypto/pqc.ts` | **Implemented** |
| **Immutable Provenance Ledger** | Air-gapped distributed ledger with SHA-256 block hash chaining and Merkle trees. | `src/ledger/dlt.ts` | **Implemented** |
| **Blind Forensic Extraction** | Standalone forensic extractor recovering session payload and querying ledger. | `src/components/ForensicStudio.tsx` | **Implemented** |
| **Tamper Auditing** | Anti-tamper verification detecting unauthorized retroactive block modifications. | `src/components/DltExplorer.tsx` | **Implemented** |
| **Adversarial Security Suite** | 7 automated cryptographic stress tests verifying negative security threat models. | `src/components/SecurityTestHarness.tsx` | **Implemented** |
| **Activity & Security Audit Center** | Cryptographic hash-chained audit log with OWASP sanitization, anomaly detection, and DLT correlation. | `src/services/auditService.ts` | **Implemented** |
| **Incident Response & Forensic Dossiers** | Stateful incident triage, evidence timeline cross-auditing, canonical JSON digests, and court-ready PDF dossiers. | `src/services/forensicDossierService.ts` | **Implemented** |
| **Offline Air-Gap Readiness** | Fully local execution in browser IndexedDB with zero runtime network calls. | `src/storage/airGappedStorage.ts` | **Implemented** |
