# ZeroProof

**Prove who you are. Reveal nothing.** A zero-knowledge identity platform: an encrypted document vault, ZK age credentials and revocable verification links.

The application backend is **Java 21 / Spring Boot 3**. The React frontend and the Circom/snarkjs PLONK circuits are kept from the original project. A tiny stateless Node script (`zkp/zk-bridge.js`) runs only the snarkjs `prove`/`verify` calls on behalf of Java. It has no HTTP server, storage or business logic.

## Architecture

```
React (Vite :5173) ──REST──► Spring Boot (:3000)
 └ browser PLONK proving        ├ controllers / services / Spring Data JPA → H2 file DB (data/java/zeroproof)
   (Web Worker + snarkjs)       ├ PDFBox + Tess4J OCR, SHA-256, AES-256-GCM vault (data/java/vault)
                                └ ZkpService ──stdin/stdout JSON──► zkp/zk-bridge.js ──► snarkjs + keys/
```

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · API: [docs/API.md](docs/API.md) · Security: [docs/SECURITY.md](docs/SECURITY.md)

## Project layout

```
backend/            Java 21 Spring Boot application (Maven, ./mvnw)
  src/main/java/com/zeroproof/
    controller/     REST endpoints
    service/        documents, extraction, credentials, shares, nullifiers, verification, ZKP, legacy import
    crypto/         SHA-256, derivations, AES-256-GCM + key handling
    entity/         JPA entities and repositories
    api/ config/    response envelope, errors, CORS, rate limiting, settings
  src/test/         unit + integration tests (real PLONK proving)
zkp/zk-bridge.js    minimal snarkjs bridge (prove / verify only)
circuits/           Circom sources (age_check, range_check, Poseidon nullifier)
keys/               compiled circuits, proving & verification keys (do not regenerate casually)
web/                React 19 + Vite frontend (public/ holds the browser proving artifacts)
scripts/            circuit compile scripts
eng.traineddata     Tesseract English model used by OCR
data/               runtime data, git-ignored (database, vault, key, legacy files)
```

## Prerequisites

- **JDK 21 or newer** (the build targets `--release 21`)
- **Node.js 18+** (frontend, and the ZKP bridge at runtime)
- Maven is **not** required: use the wrapper `backend/mvnw` (`mvnw.cmd` on Windows)
- OCR on Linux/macOS needs the Tesseract native library (`apt install libtesseract-dev` / `brew install tesseract`). Tess4J bundles it on Windows. Without it, image uploads fall back to manual entry.

## Run locally

From the repository root:

```powershell
npm install                    # snarkjs, ffjavascript, circomlib for the ZKP bridge
cd web; npm install; cd ..     # frontend dependencies
```

Terminal 1, backend (run from `backend/` so the default relative paths resolve):

```powershell
cd backend
./mvnw spring-boot:run         # http://localhost:3000  (Windows: .\mvnw.cmd spring-boot:run)
```

Terminal 2, frontend:

```powershell
cd web
npm run dev                    # http://localhost:5173
```

Packaged jar alternative: `cd backend; ./mvnw package -DskipTests; java -jar target/zeroproof-backend-3.0.0.jar` (still run from `backend/`).

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Backend port |
| `AEGISID_DOC_KEY` | unset | 64 hex chars (32-byte AES-256 key). Overrides the key file |
| `ZEROPROOF_DATA_DIR` | `../data` | Database, vault, key file and legacy files |
| `ZEROPROOF_KEYS_DIR` | `../keys` | Circuit artifacts used by the bridge |
| `ZEROPROOF_BRIDGE` | `../zkp/zk-bridge.js` | Bridge script |
| `ZEROPROOF_NODE` | `node` | Node executable |
| `ZEROPROOF_TESSDATA` | `..` | Folder containing `eng.traineddata` |
| `ZEROPROOF_CORS_ORIGIN` | `http://localhost:5173` | Allowed frontend origin(s), comma separated |
| `ZEROPROOF_RATE_LIMIT` | `100` | Requests per minute per client IP |
| `ZEROPROOF_IMPORT_LEGACY` | `false` | Run the legacy data import at startup |
| `VITE_API_URL` (frontend) | `http://localhost:3000` | Backend URL, read in `web/src/config.js` |

### Encryption key

Documents are encrypted with AES-256-GCM. The key comes from:

1. `AEGISID_DOC_KEY` if set (exactly 64 hex characters, or startup fails), otherwise
2. `data/keys/doc.key`, generated once with `SecureRandom` on first start and reused on every restart.

The key is never logged or returned by the API, and `data/` and `*.key` are git-ignored. **Back up the key.** Losing it makes stored documents unreadable. To generate one for the environment variable: `openssl rand -hex 32`.

## Tests

```powershell
cd backend
./mvnw test
```

35 tests: unit tests for hashing, derivation compatibility, AES-GCM and extraction, plus integration tests through HTTP, H2 and the **real** snarkjs bridge. They cover uploads, issuance, public verification, tampered proofs, replay (including concurrent), share expiry and revocation, rate limiting, document download and tamper detection, and legacy import. Node.js and `npm install` at the repo root are required.

Frontend checks: `cd web; npm run lint; npm run build`.

## Legacy data import

The original Node backend stored data in `data/dynamodb_mock.json`, `data/shares.json` and `data/vault/vault_<id>.enc`. To import it:

```powershell
cd backend
$env:ZEROPROOF_IMPORT_LEGACY="true"; ./mvnw spring-boot:run
```

- Source files and legacy vault files are only read, never modified or deleted. Deleting an imported document in the app does not delete its legacy file.
- Every imported proof is re-verified with snarkjs. Proofs that fail are kept but marked unverified, and public verification rejects them.
- Each legacy file is test-decrypted with the configured key. The old backend used a fresh random key on every start unless `AEGISID_DOC_KEY` was set, so legacy documents are usually **not** decryptable. Metadata, credentials and share links still import.
- The import is idempotent and writes a PII-free summary to `data/java/legacy-import-report.json`. You can unset the variable afterwards.

## ZKP artifacts

`circuits/*.circom` compile to `keys/` (and the browser copies in `web/public/`) via `npm run compile` (needs `circom` on PATH). Recompiling produces **new** proving and verification keys, which invalidates existing proofs and credentials. Only do it intentionally.

## Known limitations

- **No authentication.** This is a single-user local app; anyone who can reach port 3000 can manage the vault. Do not expose it publicly without adding auth and TLS.
- **Self-attested browser proofs.** The browser proof flow is self-attested: the circuit proves `currentYear - birthYear >= ageLimit` for whatever birth year the prover supplies. Vault credentials bind the proof to an uploaded document's hash, but the extracted date of birth is user-confirmable.
- **OCR heuristics.** Extraction is tuned for Indian ID and marks-card layouts; anything unreadable falls back to manual entry.
- **Proof latency.** Each proof operation starts a Node process (about 1–2 s; public verification re-verifies every time).
- **In-memory rate limit.** Counters reset when the backend restarts.

## License

MIT
