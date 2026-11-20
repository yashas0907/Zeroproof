# Security model

**Trust model:** single-user local app, no authentication. Do not expose publicly without adding auth and TLS.

**Cryptography**
- Documents: SHA-256 digest; AES-256-GCM encryption at rest (blob = iv16 | tag16 | ciphertext, random IV per file).
- Key: `AEGISID_DOC_KEY` (64 hex) or a persistent generated `data/keys/doc.key` (owner-only, git-ignored). Never logged, never returned by an API; startup fails on a malformed key.
- ZK: PLONK on BN128 (Circom `age_check`, `range_check`), Poseidon nullifier `Poseidon(secret, externalNullifier)`. Credential secret = `SHA256(documentHash + credentialId)` prefix; external nullifier is per credential.

**Replay prevention:** a nullifier is a primary key in the `nullifiers` table, so check-and-store is atomic and survives restarts. Invalid proofs never consume a nullifier.

**Public verification (`GET /v3/verify/{token}`)** never trusts stored flags. It requires an active, unexpired link and credential, re-verifies the stored PLONK proof, and checks the public signals are bound to the credential (external nullifier, nullifier hash, age limit, issue year) and that the nullifier is registered to it. Revoking a link requires the owning credential.

**Privacy:** public responses contain no name/DOB/raw document; only eligibility, proof system info and a hash prefix. Logs hash client IPs and contain no PII.

**Limits:** per-IP rate limit (in memory), 10 MB upload cap, image/PDF only. The legacy hardcoded "identity registry" that overwrote OCR results was removed.
