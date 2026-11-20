# API

All responses use the envelope `{ status, data, meta, error }`. Errors carry `error.code` and `error.message`.

| Method & path | Purpose | Notable errors |
|---|---|---|
| `GET /health`, `GET /` | Health / info | |
| `GET /v1/proof-types` | Supported circuits and their public-signal order | |
| `POST /v1/verify` | Verify `{ proof, publicSignals, proofType? }` (`age_check` default, or `range_check`) and consume the nullifier | 400 `VALIDATION_ERROR`, 400 `INVALID_PROOF`, 409 `NULLIFIER_REPLAYED` |
| `POST /v3/documents/upload` | Multipart field `document` (image/PDF, ≤10 MB; optional `fullName`, `dateOfBirth`, `documentType`). Hashes, encrypts, extracts name/DOB | 400 `NO_FILE`/`INVALID_FILE_TYPE`, 413 |
| `GET /v3/documents`, `GET /v3/documents/{id}`, `DELETE /v3/documents/{id}` | Metadata only | 404 `DOCUMENT_NOT_FOUND` |
| `POST /v3/credentials/issue` | `{ documentId, overrides?: { fullName, dateOfBirth, documentType } }` → generates and verifies an `age_check` proof | 400/404, 502 `ZKP_FAILED` |
| `GET /v3/credentials`, `GET /v3/credentials/{id}` | List / detail (+ active share links) | 404 |
| `DELETE /v3/credentials/{id}` | Revoke a credential | 404 |
| `POST /v3/credentials/{id}/share` | `{ expiresInHours?, organizationName? }` → share token | 409 `CREDENTIAL_INACTIVE` |
| `DELETE /v3/credentials/{id}/share` | `{ token }` revoke a link owned by this credential | 404 `SHARE_NOT_FOUND` |
| `GET /v3/verify/{token}` | Public verification | 404 `INVALID_SHARE_LINK` (unknown/expired/revoked), 410 `CREDENTIAL_REVOKED`/`CREDENTIAL_EXPIRED`, 422 `INVALID_PROOF`/`PROOF_MISMATCH`/`NO_PROOF`, 409 `NULLIFIER_MISMATCH` |

Removed from the legacy Node API: `POST /v2/verify`, `GET /v2/audit/:nullifier` (unused; `/v1/verify` now requires a non-zero nullifier) and JWT authentication (disabled by default and only guarded v2).
