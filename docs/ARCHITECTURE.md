# Architecture

```
React (Vite :5173) ──REST──► Spring Boot (:3000, Java 21)
   │                             ├─ H2 file database        data/java/zeroproof.mv.db
   │                             ├─ encrypted vault          data/java/vault/<id>.enc
   │                             └─ ZkpService ─ stdin/stdout JSON ─► node zkp/zk-bridge.js ─► snarkjs + keys/
   └─ Web Worker (snarkjs, web/public/*.wasm, *.zkey) ──► POST /v1/verify
```

## Responsibilities

- **Java (`backend/`) owns all application logic.**
  - HTTP API and validation, error envelope, CORS and rate limiting
  - document upload, PDF text (PDFBox) and OCR (Tess4J) with manual fallback, attribute extraction
  - SHA-256, AES-256-GCM and key management
  - credential issuance, nullifier registry, share links and public verification
  - persistence (Spring Data JPA, H2), legacy import, and orchestration of every ZKP step
- **`zkp/zk-bridge.js`** is a stateless snarkjs wrapper with exactly two commands, `prove` and `verify`, for `age_check` and `range_check`. It has no HTTP, storage or decisions.
- **Circuits** (`circuits/`) and artifacts (`keys/`, `web/public/`) are unchanged from the original project.

## Main flows

1. **Browser proof.** The user enters a birth year and the Web Worker proves locally. Java validates the payload, verifies the proof via the bridge, then atomically consumes the nullifier.
2. **Vault.**
   1. Upload: SHA-256 hash, duplicate check, AES-GCM encryption, text extraction.
   2. Confirm or edit the name and date of birth.
   3. Issue: derive the secret and external nullifier, prove `age_check`, verify, register the nullifier, store the credential.
   4. Create a share link.
   5. A third party opens `/verify/{token}`, and Java re-verifies the stored proof and its binding.

## Data model (H2)

| Table | Contents |
|---|---|
| `documents` | metadata, SHA-256, vault path, extraction status, import note |
| `credentials` | proof JSON, public signals, nullifier, external nullifier, issue year, eligibility, expiry, status |
| `share_links` | token, credential id, expiry, status, view count |
| `nullifiers` | nullifier hash (primary key), proof type, owning credential |

## Why a Node bridge

There is no maintained Java implementation of snarkjs-format PLONK verification on BN254. Re-implementing it would mean redesigning the cryptography. One short-lived process per call is the simplest reliable integration, at a cost of about 1–2 s per call.
