#!/usr/bin/env node
/**
 * ZeroProof ZKP bridge. A deliberately tiny, stateless snarkjs wrapper called by the Java backend.
 * It contains NO business logic: it only runs PLONK prove/verify for the existing Circom artifacts.
 *
 *   stdin  : one JSON object
 *            { "cmd": "prove",  "circuit": "age_check", "keysDir": "...", "inputs": {...} }
 *            { "cmd": "verify", "circuit": "age_check", "keysDir": "...", "proof": {...}, "publicSignals": [...] }
 *   stdout : { "ok": true, ... }  or  { "ok": false, "kind": "env" | "input", "error": "..." }
 *            kind "env"   = toolchain/artifact problem (server fault)
 *            kind "input" = the proof, signals or circuit inputs were rejected
 */
const fs = require("fs");
const path = require("path");

const CIRCUITS = new Set(["age_check", "range_check"]);

class BridgeError extends Error {
    constructor(kind, message) {
        super(message);
        this.kind = kind;
    }
}

function load(fn, what) {
    try {
        return fn();
    } catch (err) {
        throw new BridgeError("env", `${what}: ${err.message}`);
    }
}

async function main() {
    const req = load(() => JSON.parse(fs.readFileSync(0, "utf8")), "Invalid request JSON");
    if (!CIRCUITS.has(req.circuit)) throw new BridgeError("input", "Unsupported circuit");
    const keys = path.resolve(req.keysDir || "");
    const snarkjs = load(() => require("snarkjs"), "snarkjs not installed (run npm install in the repo root)");
    const { buildBn128 } = load(() => require("ffjavascript"), "ffjavascript not installed");
    // Single-threaded curve avoids worker allocation crashes on Windows.
    globalThis.curve_bn128 = await buildBn128(true);

    if (req.cmd === "verify") {
        const vkey = load(() => JSON.parse(fs.readFileSync(path.join(keys, `${req.circuit}_vkey.json`), "utf8")),
            "Verification key missing");
        if (!Array.isArray(req.publicSignals) || typeof req.proof !== "object" || req.proof === null) {
            throw new BridgeError("input", "proof and publicSignals are required");
        }
        let valid;
        try {
            valid = await snarkjs.plonk.verify(vkey, req.publicSignals, req.proof);
        } catch (err) {
            throw new BridgeError("input", `Malformed proof: ${err.message}`);
        }
        return { ok: true, valid: valid === true };
    }
    if (req.cmd === "prove") {
        const wc = load(() => require(path.join(keys, `${req.circuit}_js`, "witness_calculator.js")), "Witness calculator missing");
        const wasm = load(() => fs.readFileSync(path.join(keys, `${req.circuit}_js`, `${req.circuit}.wasm`)), "Circuit wasm missing");
        const zkey = path.join(keys, `${req.circuit}_final.zkey`);
        if (!fs.existsSync(zkey)) throw new BridgeError("env", "Proving key missing");
        const calc = await wc(wasm);
        let wtns;
        try {
            wtns = await calc.calculateWTNSBin(req.inputs, 0);
        } catch (err) {
            throw new BridgeError("input", `Circuit inputs rejected: ${err.message}`);
        }
        const { proof, publicSignals } = await snarkjs.plonk.prove(zkey, wtns);
        return { ok: true, proof, publicSignals };
    }
    throw new BridgeError("input", "Unknown command");
}

main()
    .then((out) => { process.stdout.write(JSON.stringify(out)); process.exit(0); })
    .catch((err) => {
        const kind = err instanceof BridgeError ? err.kind : "env";
        process.stdout.write(JSON.stringify({ ok: false, kind, error: String((err && err.message) || err) }));
        process.exit(1);
    });
