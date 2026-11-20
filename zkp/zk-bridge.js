#!/usr/bin/env node
/**
 * ZeroProof ZKP bridge. A deliberately tiny, stateless snarkjs wrapper called by the Java backend.
 * It contains NO business logic: it only runs PLONK prove/verify for the existing Circom artifacts.
 *
 *   stdin  : one JSON object
 *            { "cmd": "prove",  "circuit": "age_check", "keysDir": "...", "inputs": {...} }
 *            { "cmd": "verify", "circuit": "age_check", "keysDir": "...", "proof": {...}, "publicSignals": [...] }
 *   stdout : one JSON object  { "ok": true, ... }  or  { "ok": false, "error": "..." }
 */
const fs = require("fs");
const path = require("path");

const CIRCUITS = new Set(["age_check", "range_check"]);

async function main() {
    const req = JSON.parse(fs.readFileSync(0, "utf8"));
    if (!CIRCUITS.has(req.circuit)) throw new Error("Unsupported circuit");
    const keys = path.resolve(req.keysDir);
    const snarkjs = require("snarkjs");
    const { buildBn128 } = require("ffjavascript");
    // Single-threaded curve avoids worker allocation crashes on Windows.
    globalThis.curve_bn128 = await buildBn128(true);

    if (req.cmd === "verify") {
        const vkey = JSON.parse(fs.readFileSync(path.join(keys, `${req.circuit}_vkey.json`), "utf8"));
        const valid = await snarkjs.plonk.verify(vkey, req.publicSignals, req.proof);
        return { ok: true, valid: valid === true };
    }
    if (req.cmd === "prove") {
        const wc = require(path.join(keys, `${req.circuit}_js`, "witness_calculator.js"));
        const wasm = fs.readFileSync(path.join(keys, `${req.circuit}_js`, `${req.circuit}.wasm`));
        const calc = await wc(wasm);
        const wtns = await calc.calculateWTNSBin(req.inputs, 0);
        const { proof, publicSignals } = await snarkjs.plonk.prove(path.join(keys, `${req.circuit}_final.zkey`), wtns);
        return { ok: true, proof, publicSignals };
    }
    throw new Error("Unknown command");
}

main()
    .then((out) => { process.stdout.write(JSON.stringify(out)); process.exit(0); })
    .catch((err) => { process.stdout.write(JSON.stringify({ ok: false, error: String(err && err.message || err) })); process.exit(1); });
