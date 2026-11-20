# Security model

**Trust model:** a single-user local application with no authentication. Do not expose it publicly without adding auth and TLS.

## Cryptography

- **Document digest:** SHA-256 (`MessageDigest`). Used for duplicate detection, credential binding and download integrity checks.
- **Encryption at rest:** AES-256-GCM (`javax.crypto`) with a fresh 16-byte IV per file. Blob layout `iv(16) | tag(16) | ciphertext`, identical to the legacy Node format. Any tampering fails authentication.
- **Key handling:** the key comes from `AEGISID_DOC_KEY` (64 hex) or a persistent, generated `data/keys/doc.key` (owner-only permissions where supported, git-ignored). It is never logged, never returned by an API and never put in error messages. A malformed key stops startup.
- **ZK:** PLONK over BN128 with the unchanged Circom circuits `age_check` and `range_check`. The nullifier is `Poseidon(secret, externalNullifier)`.
  - Credential secret = decimal of the first 40 hex chars of `SHA256(documentHash + credentialId)`.
  - External nullifier = decimal of the first 8 hex chars of `SHA256("aegisid-credential-" + credentialId)`.
  - Both are bit-for-bit compatible with the legacy issuer, and tests check them against golden values.

## Replay prevention

Nullifiers are the primary key of the `nullifiers` table and are inserted, never merged. Check-and-store is therefore atomic across threads and restarts: concurrent submissions of the same proof yield exactly one success and the rest get 409, which is tested. A nullifier is consumed only after the proof verifies.

## Public verification

`GET /v3/verify/{token}` never trusts stored flags. It requires:

- an active, unexpired link and credential;
- a fresh cryptographic verification of the stored proof;
- public signals bound to this credential (derived external nullifier, stored nullifier hash, age limit 18, issue year);
- the nullifier registered to this credential.

A valid proof copied from another credential is rejected (tested). Only the owning credential can revoke a link.

## Input handling

- Uploads are limited to 10 MB, images or PDFs only.
- Proof payloads are checked for the PLONK fields, string signals, the exact signal count and a `currentYear` within ±1 of the real year.
- A date of birth must parse and fall between 1900 and the current year.
- The per-IP rate limit (default 100/min) uses the socket address; `X-Forwarded-For` is not trusted.

## ZKP bridge isolation

Java runs `node zkp/zk-bridge.js` with a JSON request on stdin, a timeout (60 s verify, 120 s prove), an output size cap and a bounded number of concurrent processes.

The bridge reports `input` errors separately from `env` errors. A malformed proof is treated as invalid, while a missing Node, snarkjs or key surfaces as 503 and is never misreported as "invalid proof".

## Privacy

- Public responses contain no name, date of birth or file content.
- Logs hash client IPs and contain no personal data.
- The legacy import report lists only ids and counts.
- The legacy analyzer's hardcoded "identity registry", which overwrote OCR results with specific people's identity data, was removed.

## Known risks

- No authentication or TLS: run locally.
- Browser proofs are self-attested: the prover chooses the birth year.
- The rate limiter is in memory.
