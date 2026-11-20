const app = require("../api/server");
const { generateProofPayload } = require("../prover/prover");
const crypto = require("crypto");

async function runDemo() {
    console.log("================================================================================");
    console.log("🛡️  ZEROProof (AegisID) — END-TO-END SYSTEM RUN");
    console.log("================================================================================\n");

    const PORT = 3099;
    const server = await new Promise((resolve) => {
        const s = app.listen(PORT, () => {
            console.log(`[System] Verification API Server started on http://127.0.0.1:${PORT}`);
            resolve(s);
        });
    });

    const API = `http://127.0.0.1:${PORT}`;

    try {
        // --- STEP 1: Health & API Info ---
        console.log("\n[STEP 1] Health & System Status");
        const healthRes = await fetch(`${API}/health`);
        const healthData = await healthRes.json();
        console.log("  ✓ Service:", healthData.service, "| Version:", healthData.version, "| Status:", healthData.status);

        // --- STEP 2: Client-side PLONK ZK-SNARK Proving & Verification ---
        console.log("\n[STEP 2] Generating & Verifying Real PLONK ZK-SNARK Proof (AgeCheckV2)");
        const currentYear = new Date().getFullYear();
        const birthYear = 2000; // age = currentYear - 2000 >= 18
        const ageLimit = 18;
        const secret = "9876543210123456789";
        const externalNullifier = "424242";

        console.log(`  > Private Inputs: birthYear=${birthYear}, secret=[HIDDEN]`);
        console.log(`  > Public Inputs:  currentYear=${currentYear}, ageLimit=${ageLimit}, externalNullifier=${externalNullifier}`);
        
        const startTimeProve = performance.now();
        const zkPayload = await generateProofPayload(birthYear, currentYear, ageLimit, secret, externalNullifier);
        const proveDuration = (performance.now() - startTimeProve).toFixed(2);
        console.log(`  ✓ PLONK Proof successfully generated in ${proveDuration}ms`);
        console.log("  ✓ Public Signals emitted:", zkPayload.publicSignals);

        // Submit to /v1/verify
        console.log("  > Submitting proof to POST /v1/verify...");
        const verifyRes = await fetch(`${API}/v1/verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                proof: zkPayload.proof,
                publicSignals: zkPayload.publicSignals,
                proofType: "age_check"
            })
        });
        const verifyData = await verifyRes.json();
        console.log("  ✓ Verification Response:", {
            verified: verifyData.data.verified,
            isEligible: verifyData.data.isEligible,
            nullifierUsed: verifyData.data.nullifierUsed,
            signals: verifyData.data.signals
        });

        // Replay attempt (should detect used nullifier)
        console.log("\n[STEP 3] Testing Nullifier Replay Attack Prevention");
        const replayRes = await fetch(`${API}/v1/verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                proof: zkPayload.proof,
                publicSignals: zkPayload.publicSignals,
                proofType: "age_check"
            })
        });
        const replayData = await replayRes.json();
        if (replayRes.status === 409 || replayData.error?.code === "NULLIFIER_REPLAYED") {
            console.log("  ✓ Replay attempt successfully BLOCKED! Status 409 NULLIFIER_REPLAYED");
        } else {
            console.log("  ⚠ Replay response:", replayRes.status, replayData);
        }

        // --- STEP 4: Encrypted Document Ingestion (Vault) ---
        console.log("\n[STEP 4] Encrypted Document Upload & Extraction (POST /v3/documents/upload)");
        const dummyPdf = Buffer.from(
            "%PDF-1.4\n%\n1 0 obj\n<< /Title (Identity Document) /Author (Government Authority) >>\nendobj\n" +
            "NATIONAL IDENTITY CARD\nCandidate's Name: Alice Smith\nDate of Birth: 15/08/1998\nCard Number: 9540-5002-0568\n"
        );
        const formData = new FormData();
        const blob = new Blob([dummyPdf], { type: "application/pdf" });
        formData.append("document", blob, "national_id.pdf");
        formData.append("fullName", "Alice Smith");
        formData.append("dateOfBirth", "1998-08-15");
        formData.append("documentType", "id_card");

        const uploadRes = await fetch(`${API}/v3/documents/upload`, {
            method: "POST",
            body: formData
        });
        const uploadData = await uploadRes.json();
        const doc = uploadData.data.document;
        console.log("  ✓ Document Stored and AES-256-GCM Encrypted:");
        console.log("    - Document ID:   ", doc.id);
        console.log("    - SHA-256 Digest:", doc.documentHash);
        console.log("    - Extracted Name:", doc.attributes.name);
        console.log("    - Extracted DOB: ", doc.attributes.dob);
        console.log("    - Verified:      ", doc.isVerified);

        // --- STEP 5: Issue ZK Credential bound to Document Hash ---
        console.log("\n[STEP 5] Issuing Document-Bound ZK Credential (POST /v3/credentials/issue)");
        const issueRes = await fetch(`${API}/v3/credentials/issue`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                documentId: doc.id,
                credentialType: "age_verification"
            })
        });
        const issueData = await issueRes.json();
        const cred = issueData.data.credential;
        console.log("  ✓ Credential Issued & Bound:");
        console.log("    - Credential ID:  ", cred.id);
        console.log("    - Credential Type:", cred.credentialType);
        console.log("    - Age / Eligible: ", cred.age, "years old / Eligible:", cred.isEligible);
        console.log("    - Document Binding:", cred.binding);
        console.log("    - ZK Proof Verified:", cred.zkProof?.verified, "(Circuit:", cred.zkProof?.circuit, ")");

        // --- STEP 6: Generate Share Link ---
        console.log("\n[STEP 6] Generating Revocable Share Link (POST /v3/credentials/:id/share)");
        const shareRes = await fetch(`${API}/v3/credentials/${cred.id}/share`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                organizationName: "Consulate / Bank Verifier",
                expiresInHours: 48
            })
        });
        const shareData = await shareRes.json();
        const shareLink = shareData.data.shareLink;
        console.log("  ✓ Share Link Generated:");
        console.log("    - Token:        ", shareLink.token);
        console.log("    - Verify URL:   ", shareLink.verifyUrl);
        console.log("    - Shared With:  ", shareLink.organizationName);
        console.log("    - Expires At:   ", shareLink.expiresAt);

        // --- STEP 7: Public Zero-PII Verification ---
        console.log("\n[STEP 7] Third-Party Public Verification (GET /v3/verify/:token)");
        const publicVerifyRes = await fetch(`${API}/v3/verify/${shareLink.token}`);
        const publicVerifyData = await publicVerifyRes.json();
        const pubVer = publicVerifyData.data.verification;
        console.log("  ✓ Public Verification Query Result (Zero Raw PII exposed):");
        console.log("    - Verified:           ", pubVer.verified);
        console.log("    - Eligible:           ", pubVer.eligible);
        console.log("    - Proof Hash:         ", pubVer.proofHash);
        console.log("    - Document Prefix:    ", pubVer.documentBinding.documentHashPrefix);
        console.log("    - Shared With:        ", pubVer.sharedWith);
        console.log("    - Verification Count: ", pubVer.verificationCount);

        console.log("\n================================================================================");
        console.log("🎉 ALL ZEROProof WORKFLOWS EXECUTED SUCCESSFULLY!");
        console.log("================================================================================");
    } catch (err) {
        console.error("\n❌ Error during execution:", err);
    } finally {
        server.close();
    }
}

runDemo();

