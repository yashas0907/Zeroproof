# Architecture

```
React (Vite) --> Spring Boot --> H2 (data/java/) + encrypted vault (data/java/vault/)
   |                 `--> zkp/zk-bridge.js --> snarkjs (PLONK prove/verify) + keys/
   `-- browser proving (Web Worker) --> POST /v1/verify
```

- **Java owns all application logic**: HTTP API, validation, document processing (PDFBox, Tess4J), hashing, encryption, credentials, nullifiers, share links, persistence and orchestration of the ZKP workflow.
- **zk-bridge.js** is a stateless ~50-line wrapper: `prove` and `verify` for `age_check`/`range_check` using `keys/`. JSON in on stdin, JSON out on stdout. No HTTP, storage or decisions.
- **Circuits** (`circuits/`) and artifacts (`keys/`, `web/public/`) are unchanged from the original project; rebuild with `npm run compile` (needs `circom`).
- **Flows**: (1) the browser proves locally and the server verifies and consumes the nullifier; (2) vault: upload, extract, issue credential (server proves and verifies), share link, public verification that re-verifies the proof.
