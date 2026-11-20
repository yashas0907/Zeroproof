# ZeroProof

**Prove who you are. Reveal nothing.** A zero-knowledge identity platform: encrypted document vault, ZK age credentials and revocable share links.

The application backend is **Java 21 / Spring Boot**. The React frontend and the Circom/snarkjs PLONK circuits are unchanged; a tiny stateless Node script (`zkp/zk-bridge.js`) runs only the snarkjs prove/verify calls for the Java backend.

## Architecture

```
React (Vite :5173) ──REST──► Spring Boot (:3000)
 └ browser PLONK proving        ├ controllers / services / JPA, H2 file DB (data/java/)
   (Web Worker, snarkjs)        ├ PDFBox + Tess4J OCR, SHA-256, AES-256-GCM vault
                                └ ZkpService ──stdin/stdout JSON──► zkp/zk-bridge.js (snarkjs prove/verify only)
```

| Concern | Where |
|---|---|
| REST API, validation, errors, rate limit | `backend/src/main/java/com/zeroproof/{controller,api,config}` |
| Documents, extraction, credentials, shares, nullifiers | `backend/.../service`, `entity` |
| Hashing / encryption / key handling | `backend/.../crypto` |
| Circuits and keys | `circuits/`, `keys/` (compile with `npm run compile`) |
| ZKP bridge | `zkp/zk-bridge.js` |
| Frontend | `web/` |

## Run locally

Prerequisites: **JDK 21+**, **Node.js 18+**.

```powershell
npm install                      # snarkjs / circomlib for the ZKP bridge (repo root)
cd web; npm install; cd ..       # frontend

cd backend; ./mvnw spring-boot:run     # terminal 1 -> http://localhost:3000
cd web; npm run dev                    # terminal 2 -> http://localhost:5173
```

Run the tests (includes real PLONK proving and the full document workflow):

```powershell
cd backend; ./mvnw test
```

### Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Backend port |
| `AEGISID_DOC_KEY` | _(unset)_ | 64-hex-char AES-256 key. If unset, a key is generated once into `data/keys/doc.key` and reused on every restart |
| `ZEROPROOF_CORS_ORIGIN` | `http://localhost:5173` | Allowed frontend origin(s), comma separated |
| `ZEROPROOF_RATE_LIMIT` | `100` | Requests per minute per IP |
| `ZEROPROOF_DATA_DIR` | `../data` | Database, vault and key location |
| `ZEROPROOF_IMPORT_LEGACY` | `false` | One-time import of the old Node `data/*.json` (documents' ciphertext stays unreadable if it was encrypted with a per-boot random key) |
| `VITE_API_URL` (frontend) | `http://localhost:3000` | Backend URL |

`data/` (database, encrypted vault, key file) is git-ignored. **Back up `data/keys/doc.key` (or set `AEGISID_DOC_KEY`)**: without it, stored documents cannot be decrypted.

## API

See [docs/API.md](docs/API.md). Core flow: `POST /v3/documents/upload` → `POST /v3/credentials/issue` → `POST /v3/credentials/{id}/share` → public `GET /v3/verify/{token}`; plus `POST /v1/verify` for browser-generated proofs.

## Security notes

See [docs/SECURITY.md](docs/SECURITY.md). Highlights: public verification re-runs the PLONK verification and checks the proof is bound to the credential; nullifiers are single-use (database primary key); expired and revoked links/credentials are rejected; the encryption key is never logged or returned.

There is no user authentication: this is a single-user local application. Do not expose it to the internet as-is.

## Known limitations

- OCR uses Tesseract via Tess4J with heuristics tuned for Indian IDs and marks cards. If OCR cannot read a document the UI asks for manual entry.
- Each proof operation starts a Node process (~1-2 s).
- Rate limiting is in memory and resets on restart.

## License

MIT
