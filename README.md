# SIH 26237: Post-Quantum Document Enclave & Forensic Attribution

[![Repository](https://img.shields.io/badge/GitHub-manoj--9899%2Fsih-blue?logo=github)](https://github.com/manoj-9899/sih)
[![NIST FIPS 203](https://img.shields.io/badge/PQC-ML--KEM--768-emerald)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST FIPS 204](https://img.shields.io/badge/PQC-ML--DSA--65-emerald)](https://csrc.nist.gov/pubs/fips/204/final)
[![Air-Gapped](https://img.shields.io/badge/Runtime-100%25%20Air--Gapped%20Offline-indigo)]()
[![Tests](https://img.shields.io/badge/Tests-207%2F207%20Passing-brightgreen)]()

> **Author / Lead Developer:** **Manoj Pawar** ([@manoj-9899](https://github.com/manoj-9899))  
> **Official Repository:** [https://github.com/manoj-9899/sih](https://github.com/manoj-9899/sih)  
> **Problem Statement:** SIH 26237 — Post-Quantum Document Enclave with Provenance & Dynamic Steganography

---

## 💡 What Is This Project?

When a classified document is encrypted and sent to multiple people (**Alice**, **Bob**, and **Charlie**), traditional encryption hands everyone the **exact same copy**.

If someone leaks that document to the press or internet:
* All copies look identical.
* Everyone can deny responsibility: *"It wasn't me, someone else leaked it."*
* There is no cryptographic proof of who broke confidentiality.

**This project solves that problem.**

By coupling **Post-Quantum Cryptography (PQC)**, **Dynamic Invisible Watermarking**, and an **Air-Gapped Immutable Ledger (DLT)**:
1. **Decryption is Accountable:** Plaintext is never released until the recipient signs the decryption event with a post-quantum digital signature.
2. **Invisible Attribution:** At decryption time, the enclave silently embeds an invisible forensic watermark unique to that recipient and session.
3. **Definitive Leak Attribution:** If the text is leaked anywhere, the **Forensic Studio** instantly extracts the hidden payload, audits the immutable ledger, and mathematically proves the leaker's identity with 100% certainty.

---

## ⚡ Quick Start

Get the entire workstation running locally in under 2 minutes:

### 1. Clone the repository
```bash
git clone https://github.com/manoj-9899/sih.git
cd sih
```

### 2. Install dependencies
```bash
npm install
```

### 3. Start the application
```bash
npm run dev
```

Open your browser to:
```text
http://localhost:3000
```

> **Note:** The application runs **100% offline** in your browser. No external API keys, cloud subscriptions, or internet connection required after `npm install`.

---

## 🚀 5-Minute Interactive Demo Walkthrough

Once the application is running, follow these simple steps to see the entire security lifecycle in action:

| Step | Screen | Action | What to Observe |
| :---: | :--- | :--- | :--- |
| **1** | **Sender Studio** | Select `OPERATION AEGIS`, choose **Alice** & **Bob** (leave Charlie unchecked), and click **Encrypt & Dispatch**. | Creates broadcast package with individual **ML-KEM-768** envelopes for authorized recipients. |
| **2** | **Recipient Portal** | Select **Dr. Alice Vance** and click **Decrypt & Bind Provenance Event**. | Runs 6-stage pipeline: decapsulates key, decrypts ciphertext, embeds zero-width watermark, signs with **ML-DSA-65**, and anchors to ledger. |
| **3** | **Recipient Portal** | Switch persona to **Charlie Chen**. | Access rejected (`ACCESS REJECTED (NO ENVELOPE)`). Unauthorized persons cannot decrypt. |
| **4** | **Forensic Studio** | Switch back to Alice and click **Simulate Leak of Dr. Alice Vance's Copy**, then click **Execute Blind Forensic Attribution**. | Blind steganographic extraction recovers session payload, queries ledger, and issues a court-ready **Forensic Attribution Certificate** identifying Alice as the leaker. |
| **5** | **DLT Explorer** | Click **Audit Entire Chain**, then test **Simulate Rogue Admin Tamper**. | Proves cryptographic immutability: any alteration to historical records is immediately detected by the Merkle validator quorum. |
| **6** | **Attack Lab** | Click **Run All Security Tests**. | Automated adversarial suite tests bit-flips, fake signatures, and envelope isolation live. |

---

## 🛡️ Key Capabilities

* **Quantum-Resistant Encryption (NIST FIPS 203):**  
  Uses **ML-KEM-768** (Kyber lattice cryptography) to encapsulate symmetric keys for each recipient, eliminating RSA/ECC vulnerability to future quantum computers.
* **Non-Repudiable Digital Signatures (NIST FIPS 204):**  
  Uses **ML-DSA-65** (Dilithium) to sign RFC 8785 canonical JSON decryption records prior to releasing document plaintext.
* **Imperceptible Steganography:**  
  Encodes a 32-byte binary payload into zero-width Unicode whitespace characters. The text looks completely normal to humans and word processors ($SSIM \ge 0.9998$).
* **Offline Immutable Distributed Ledger (DLT):**  
  Runs a permissioned, air-gapped local blockchain with SHA-256 block chaining, binary Merkle tree proofs, and a 3/3 validator quorum.
* **Portable Encrypted Packages (`.sihpkg`):**  
  Supports exporting and importing encrypted multi-recipient containers with cryptographic tamper validation and quarantine controls.
* **Forensic Dossiers & Incident Response:**  
  Generates automated tamper-evident incident response dossiers exportable as both machine-readable JSON and signed forensic PDFs.

---

## 📐 Cryptographic Specifications

| Component | Standard / Algorithm | Parameters | Purpose |
| :--- | :--- | :--- | :--- |
| **Key Encapsulation** | **NIST FIPS 203 (ML-KEM)** | `ML-KEM-768` | Quantum-safe key encapsulation per recipient |
| **Digital Signatures** | **NIST FIPS 204 (ML-DSA)** | `ML-DSA-65` | Non-repudiation signature on decryption event |
| **Symmetric Encryption** | **NIST SP 800-38D** | `AES-256-GCM` | High-speed authenticated document encryption |
| **Canonical Serialization** | **RFC 8785** | Canonical JSON | Deterministic message hashing across platforms |
| **Integrity & Commitments** | **FIPS 180-4** | `SHA-256` | Merkle roots, watermark commitments, block hashes |
| **Local Keystore Security** | **NIST SP 800-132** | `PBKDF2-HMAC-SHA256` | 100,000 rounds deriving browser storage keys |

---

## 🧪 Testing & Verification

The project includes an exhaustive end-to-end and adversarial security test suite:

```bash
# Run all 207 automated security & cryptographic unit tests
npm test

# Run TypeScript typecheck / lint
npm run lint

# Compile production bundle
npm run build
```

### Test Coverage Highlights:
- **E2E Security Suite (`tests/e2e_security_validation.test.ts`)**: Validates full lifecycle, revocation enforcement, package isolation, cross-document transplant detection, and storage persistence.
- **Post-Quantum Crypto Suites**: ML-KEM-768 encapsulation/decapsulation and ML-DSA-65 sign/verify test vectors.
- **DLT Quorum & Multi-Node Replication**: Validates consensus, Merkle inclusion proofs, tamper detection, and socket replication across validators.
- **Steganography & Forensic Extraction**: Validates 32-byte payload round-tripping, CRC-16 integrity, and blind extraction from zero-width unicode streams.

---

## 📂 Project Directory Structure

```text
sih/
├── src/
│   ├── crypto/           # ML-KEM-768, ML-DSA-65, AES-256-GCM, Session Manager
│   ├── watermark/        # Zero-width steganography engine, CRC-16, metrics
│   ├── ledger/           # Offline DLT blockchain, Merkle trees, validator quorum
│   ├── services/         # Distribution service, audit service, incident engine
│   ├── storage/          # Air-gapped IndexedDB persistence layer
│   ├── components/       # Dark-mode defense workstation UI screens & modals
│   └── types/            # TypeScript interfaces for envelopes, events, and dossiers
├── tests/                # 21 test suites (207 passing tests)
├── package.json          # Node.js dependencies and scripts
└── vite.config.ts        # Vite configuration
```

---

## 🔒 Security & Air-Gap Model

* **100% Local Execution:** Runs entirely inside the browser using native Web Cryptography and WebAssembly. Zero telemetry, zero external CDN assets, zero external network requests.
* **Fail-Closed Security:** Decryption operations fail immediately if envelopes are revoked, recipients are deactivated, or packages are flagged for isolation.
* **Strict AAD Binding:** Decryption strictly enforces Additional Authenticated Data binding to prevent ciphertext transplantation across documents.

---

## 📄 Author & Attribution

* **Lead Developer:** **Manoj Pawar** ([@manoj-9899](https://github.com/manoj-9899))
* **Project:** Developed for **Smart India Hackathon (SIH 26237)**
* **Repository:** [https://github.com/manoj-9899/sih](https://github.com/manoj-9899/sih)
