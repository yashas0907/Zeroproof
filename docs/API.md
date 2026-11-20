# API

Base URL `http://localhost:3000`. Every response except `/health`, `/` and file downloads uses the envelope:

```json
{ "status": "success" | "error", "data": { ... } | null, "meta": { "requestId", "version", "timestamp" }, "error": null | { "code", "message" } }
```

Every response carries `X-Request-ID`, `X-RateLimit-Limit` and `X-RateLimit-Remaining`. Over the limit the server returns 429 `RATE_LIMITED` with `Retry-After`.

## Proof verification

| Method & path | Body / result | Errors |
|---|---|---|
| `GET /v1/proof-types` | circuits and their public-signal order | |
| `POST /v1/verify` | `{ proof, publicSignals: string[], proofType?: "age_check" \| "range_check" }` → `{ verified, isEligible, proofType, nullifierUsed, signals }` | 400 `VALIDATION_ERROR` (shape, signal count, implausible `currentYear`, zero nullifier), 400 `INVALID_PROOF`, 409 `NULLIFIER_REPLAYED`, 503 `ZKP_UNAVAILABLE` |

Signal order: `age_check` = `[isEligible, nullifierHash, currentYear, ageLimit, externalNullifier]`; `range_check` = `[inRange, nullifierHash, currentYear, minAge, maxAge, externalNullifier]`. A nullifier is consumed only after the proof verifies.

## Documents

| Method & path | Notes | Errors |
|---|---|---|
| `POST /v3/documents/upload` | multipart `document` (image or PDF, ≤ 10 MB); optional `fullName`, `dateOfBirth`, `documentType` fallbacks. Returns `document {id, originalName, documentHash, attributes{name, dob, documentType, status, reason}, duplicate, isVerified, createdAt}`. `status` is `SUCCESS`, `NO_DATA_FOUND` or `UNREADABLE` (manual entry needed) | 400 `NO_FILE`, 400 `INVALID_FILE_TYPE`, 413 `FILE_TOO_LARGE` |
| `GET /v3/documents` | active documents (metadata only) | |
| `GET /v3/documents/{id}` | metadata | 404 `DOCUMENT_NOT_FOUND` |
| `GET /v3/documents/{id}/file` | decrypted original, integrity-checked against the stored SHA-256 (`Cache-Control: no-store`) | 404, 409 `DOCUMENT_UNREADABLE` (wrong key or tampered), 409 `DOCUMENT_INTEGRITY_ERROR`, 410 `DOCUMENT_FILE_MISSING` |
| `DELETE /v3/documents/{id}` | soft delete; removes ciphertext written by this backend (never legacy files) | 404 |

## Credentials and share links

| Method & path | Notes | Errors |
|---|---|---|
| `POST /v3/credentials/issue` | `{ documentId, credentialType?, overrides?: { fullName, dateOfBirth (YYYY-MM-DD), documentType } }`. Generates and verifies an `age_check` proof (age limit 18) and registers its nullifier | 400 `MISSING_DOCUMENT_ID`, 400 `INVALID_DATE_OF_BIRTH`, 404 `DOCUMENT_NOT_FOUND`, 502 `ZKP_FAILED`, 503 `ZKP_UNAVAILABLE` |
| `GET /v3/credentials[?documentId=]` | non-revoked credentials | |
| `GET /v3/credentials/{id}` | detail + active share links | 404 `CREDENTIAL_NOT_FOUND` |
| `DELETE /v3/credentials/{id}` | revoke credential | 404 |
| `POST /v3/credentials/{id}/share` | `{ expiresInHours? (1–8760, default 72), organizationName? }` → `shareLink {token, verifyUrl, organizationName, expiresAt, status}` | 400, 404, 409 `CREDENTIAL_INACTIVE` |
| `DELETE /v3/credentials/{id}/share` | `{ token }`; only the owning credential can revoke | 400 `MISSING_TOKEN`, 404 `SHARE_NOT_FOUND` |

## Public verification

`GET /v3/verify/{token}` returns `verification {verified, eligible, isEligible, proofHash, credentialType, zkProof{verified, circuit, proofSystem, curve}, documentBinding{documentHashPrefix, bindingMethod}, sharedWith, issuedAt, expiresAt, verificationCount, timestamp}`. It contains no name, date of birth or document content.

The check order: the link must exist and be neither revoked nor expired (404 `INVALID_SHARE_LINK`). The credential must exist (404), not be revoked (410 `CREDENTIAL_REVOKED`) and not be expired (410 `CREDENTIAL_EXPIRED`). The stored proof must exist (422 `NO_PROOF`) and pass a fresh PLONK verification (422 `INVALID_PROOF`). Its signals must be bound to the credential (422 `PROOF_MISMATCH`), and its nullifier must be registered to the credential (409 `NULLIFIER_MISMATCH`). The view counter increments only on success.

## Removed from the legacy Node API

- `POST /v2/verify` and `GET /v2/audit/:nullifier`: unused by the frontend. `/v1/verify` now always requires a non-zero nullifier, and the audit endpoint leaked nullifier usage without authentication.
- JWT middleware: it was disabled by default, only guarded v2, and used a hardcoded fallback secret.
- AWS (S3, DynamoDB, Lambda/SAM).
