# 🛡️ AegisID (Zeroproof) v3.0

### Zero-Knowledge Identity Platform & Document Vault

**Prove who you are. Reveal nothing.**

[![CI](https://github.com/Sohan258oss/Zeroproof/actions/workflows/ci.yml/badge.svg)](https://github.com/Sohan258oss/Zeroproof/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

*Privacy-preserving identity verification with client-side ZK-SNARK proving, encrypted document vaulting, and revocable trust sharing.*

---

## What is AegisID?

AegisID is a privacy-first identity platform that eliminates the need to expose sensitive identity documents during everyday verification. It operates across two primary workflows:

1. **Client-Side Prover (Zero PII Exposure)**: Generates PLONK zero-knowledge proofs directly inside the browser using WebAssembly. Private credentials (such as birth years or secret seeds) never leave the user's browser, transmitting only mathematical proofs to the verifier.
2. **Encrypted Document Vault**: Allows users to store scanned identity documents (e.g., National IDs, PAN cards, grade certificates) in an AES-256-GCM encrypted vault, extract required attributes, and issue cryptographically bound ZK credentials with revocable third-party verification links.

Third-party verifiers can confirm eligibility criteria (e.g., "holder is at least 18 years old") via public verification tokens **without ever accessing the underlying raw document or personal data**.

---

## Architecture & Data Flow

```
══════════════════════════════════════════════════════════════════════════════
FLOW 1: CLIENT-SIDE ZK PROVER (Browser Sandbox)
══════════════════════════════════════════════════════════════════════════════
[User Inputs] ──► [Browser Web Worker] ──► [snarkjs / WASM Prover]
 (Year, Limit)     (Sandboxed Execution)    (Evaluates PLONK Constraints)
                                                        │
                                                        ▼ Generates Proof
                                                 [PLONK Proof Payload]
                                                 (Zero PII Transmitted)
                                                        │
                                                        ▼ POST /v1/verify
                                              [AegisID Verifier Node]
                                              (Checks Polynomials < 50ms)

══════════════════════════════════════════════════════════════════════════════
FLOW 2: DOCUMENT VAULT & CREDENTIAL ISSUANCE
══════════════════════════════════════════════════════════════════════════════
[Upload Document] ──► [POST /v3/documents/upload] ──► [Analyzer: Tesseract / PDF]
 (PDF, PNG, JPG)       (Server-Side Ingestion)         (Extracts Name & DOB)
                                                              │
   ┌──────────────────────────────────────────────────────────┴───────────────┐
   ▼                                                                          ▼
[AES-256-GCM Vault]                                                [Extracted Metadata]
(Encrypted Disk/S3 Blob)                                           (User Review & Confirm)
                                                                              │
                                                                              ▼
                                                                  [POST /v3/credentials/issue]
                                                                  (SHA-256 Doc Hash ──► Secret)
                                                                  (Issues Bound ZK Credential)
                                                                              │
                                                                              ▼
                                                                  [Share Token /verify/:token]
                                                                  (Public Link: 0% Raw PII)
```

---

## Core Features

### 1. Zero-Knowledge Cryptography
- **PLONK Proving System**: Uses universal trusted setup on the BN128 (BN254) elliptic curve, eliminating the need for circuit-specific ceremonies.
- **Poseidon Nullifiers**: In-circuit Poseidon hash constraints (`Poseidon(secret, externalNullifier)`) prevent replay attacks within identical contexts while maintaining cross-service unlinkability.
- **Age Threshold & Range Circuits**:
  - `AgeCheckV2`: Proves `currentYear - birthYear >= ageLimit` with server-validated public timestamp constraints.
  - `RangeCheck`: Proves `minAge <= age <= maxAge` without revealing the exact birth year.
- **Cryptographic Document Binding**: Credentials link the document's SHA-256 digest to the circuit's secret seed (`SHA-256(documentHash + credentialId)`), cryptographically anchoring the verified credential to the source file.

### 2. Document Vault & Privacy
- **AES-256-GCM Storage Encryption**: Document binaries are encrypted using authenticated AES-256-GCM before writing to the storage layer. In production, encryption keys are loaded via the `AEGISID_DOC_KEY` environment variable (with an ephemeral fallback for local development).
- **Zero-PII Public Verification**: Third-party verification links (`GET /v3/verify/:token`) return only cryptographic verification proofs, eligibility booleans, credential types, binding prefixes, and expiration timestamps. Raw personal attributes and file blobs are never returned.
- **Revocation & Expiration**: Share links and credentials can be revoked on-demand, causing external verification requests to fail immediately.

### 3. Document Extraction Pipeline
- **Multi-Format Extraction**: Ingests PDFs and images (PNG, JPEG), utilizing `pdf-parse` and `tesseract.js` OCR.
- **Pattern Matching**: Specialized regex heuristics extract names, document numbers, and dates of birth from supported identity document formats (including Indian Aadhaar and PAN cards).
- **Interactive Verification & Fallback**: When documents lack explicit dates of birth (e.g., educational marks cards) or have noisy scans, the frontend prompts the user to verify or manually input missing parameters before signing.

### 4. API Security & Controls
- **In-Memory Rate Limiting**: An in-memory sliding-window rate limiter (default: 100 requests/minute per IP) protects API verification endpoints from brute-force lookups (resets on server restart).
- **Input Sanitization**: Request structures, nullifier formats, and public signal types are strictly validated before proof verification.

---

## Proving System Specifications

| Feature | PLONK (AegisID) | Groth16 | Halo2 |
|---|---|---|---|
| **Trusted Setup** | Universal (Powers of Tau) | Per-circuit ceremony | None (transparent) |
| **Proof Size** | ~768 bytes (raw binary); ~1.8 KB (JSON-serialized) | ~192 bytes | Variable |
| **Verification Time** | ~10–30ms (typically < 50ms) | ~5ms | ~20ms |
| **Curve** | BN128 / BN254 | BN128 / BLS12-381 | Pasta curves |
| **Circuit Constraints** | ~290 constraints (`AgeCheckV2`) | ~280 constraints | Higher overhead |

*Note: Benchmarks reflect modern consumer x86-64/ARM hardware under single-threaded Node.js execution.*

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Circuits** | Circom 2.1, circomlib |
| **Prover Engine** | snarkjs (PLONK), ffjavascript (single-threaded WASM mode) |
| **Hash Functions** | Poseidon (in-circuit nullifiers), SHA-256 (document digests & bindings) |
| **Frontend** | React 19, Vite 7, TailwindCSS 4, Web Workers |
| **Backend** | Express 5, Node.js (>= 18.0.0) |
| **Document Processing** | Tesseract.js, pdf-parse, Multer |
| **Current Deployment** | Standalone Node.js service with local encrypted disk storage & JSON metadata |
| **Cloud Templates (IaC)** | AWS SAM (`cloud/template.yaml`), AWS Lambda (ARM64), DynamoDB, S3 |
| **CI Pipeline** | GitHub Actions (Lint, Build, API tests, Security audit) |

---

## Automated Testing & CI

The repository maintains an automated test suite verifying cryptographic correctness, API contracts, rate limiting, and document storage:

* **Comprehensive Test Suite** (`tests/comprehensive.test.js`): **151 tests** covering all endpoints, negative test cases, rate limits, duplicate upload handling, encryption/decryption cycles, credential issuance, and revocation.
* **API Integration Tests** (`tests/api.test.js`): **23 tests** validating route status codes, header compliance, and PLONK payload validation.
* **End-to-End Flow Test** (`tests/v3_flow.test.js`): **4 tests** tracing upload, ZK issuance, sharing, and public token verification.
* **Total Verified Tests**: **178 passing tests** (0 failed).

### Active GitHub Actions CI
The CI workflow ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs on push and pull requests targeting `main` across Node.js `20.x` and `22.x`:
1. **Frontend Linting**: ESLint flat configuration across all React components and worker scripts (`npm --prefix web run lint`).
2. **Frontend Compilation**: Production bundle generation via Vite (`npm --prefix web run build`).
3. **Automated Tests**: Complete test execution against the API server.
4. **Security Audit**: Dependency vulnerability scans (`npm audit`).

---

## Quick Start (Local Setup)

The application runs in two independent processes: the backend verification server and the frontend client.

### Prerequisites
- Node.js >= 18.0.0 (Node 20.x or 22.x recommended)
- npm >= 9.0.0

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Sohan258oss/Zeroproof.git
cd Zeroproof

# Install backend dependencies
npm install

# Install frontend dependencies
cd web && npm install && cd ..
```

### 2. Start the Backend API (Terminal 1)
```bash
npm start
# Runs on http://localhost:3000
```

### 3. Start the Frontend Application (Terminal 2)
```bash
npm run web
# Runs on http://localhost:5173
```

---

## Project Structure

```
Zeroproof/
├── api/                   # Express 5 API server
│   ├── middleware/        # Rate limiting & timing middleware
│   ├── routes/v1, v2, v3/ # Versioned endpoints (v1 proof, v2 audit, v3 vault/credentials)
│   ├── services/          # Cloud store (S3/local), document analyzer, credential issuer
│   └── utils/             # Standardized API response formatters & error classes
├── web/                   # React 19 + Vite 7 frontend application
│   ├── src/
│   │   ├── components/    # Proof generator, timeline, stats panel, badges
│   │   ├── pages/         # Prover demo (/), Vault (/vault), Upload, Detail, Public Verify
│   │   └── workers/       # Web Worker for non-blocking client-side PLONK proving
│   └── public/            # Compiled circuit WASM and zkey artifacts
├── circuits/              # Circom ZK circuit source files
│   ├── age_check.circom   # Age threshold verification with Poseidon nullifier
│   ├── range_check.circom # Age range verification circuit
│   └── lib/               # Shared nullifier templates
├── cloud/                 # AWS Serverless Application Model (SAM) templates
│   ├── template.yaml      # AWS SAM definition (Lambda, API Gateway, DynamoDB)
│   └── lambda_handler.js  # Serverless handler for AWS deployment
├── keys/                  # Circuit keys, WASM binaries, and verification keys
├── tests/                 # Automated test suites (comprehensive, API, and flow)
└── docs/                  # Architectural documentation and threat models
```

---

## Deployment Status & Future Cloud Architecture

- **Current Deployment Status**: The application is configured and actively running as a **local standalone application**. All vault storage and metadata tracking use local filesystem fallbacks (`data/vault/` and `data/dynamodb_mock.json`).
- **AWS Cloud Templates**: The repository contains production-ready Infrastructure as Code (IaC) templates in [`cloud/template.yaml`](cloud/template.yaml) and [`cloud/lambda_handler.js`](cloud/lambda_handler.js). Teams wishing to deploy AegisID to AWS can deploy the serverless stack using AWS SAM CLI (`sam build`, `sam deploy`) and connect to Amazon S3 and Amazon DynamoDB by providing standard AWS IAM credentials.
- **Automated AWS CD**: The automated deployment workflow is currently dormant pending cloud account provisioning.

---

## Known Scope & Current Limitations

1. **Document Parsing Scope**: OCR relies on open-source heuristics (`tesseract.js`). Blurry images, unsupported document formats, or IDs lacking printed birthdates require user confirmation or manual field entry before signing.
2. **Encryption Key Persistence**: In local development without `AEGISID_DOC_KEY` configured in the environment, an ephemeral encryption key is generated per server boot. Production deployments must specify a static 32-byte hexadecimal key or integrate with AWS KMS.
3. **Rate Limiting Persistence**: Rate limiting is tracked in server memory; restarting the server process resets IP sliding-window counters.

---

## License

This project is licensed under the [MIT License](LICENSE).
