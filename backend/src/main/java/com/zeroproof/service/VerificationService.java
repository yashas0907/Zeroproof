package com.zeroproof.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeroproof.api.ApiException;
import com.zeroproof.crypto.Hashing;
import com.zeroproof.entity.CredentialEntity;
import com.zeroproof.entity.NullifierEntity;
import com.zeroproof.entity.ShareLinkEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class VerificationService {
    private static final Logger log = LoggerFactory.getLogger(VerificationService.class);
    private static final List<String> PLONK_FIELDS = List.of("A", "B", "C", "Z", "T1", "T2", "T3", "Wxi", "Wxiw");

    private final ZkpService zkp;
    private final NullifierService nullifiers;
    private final CredentialService credentials;
    private final ShareService shares;
    private final ObjectMapper mapper = new ObjectMapper();

    public VerificationService(ZkpService zkp, NullifierService nullifiers, CredentialService credentials, ShareService shares) {
        this.zkp = zkp;
        this.nullifiers = nullifiers;
        this.credentials = credentials;
        this.shares = shares;
    }

    /** POST /v1/verify: verify a PLONK proof, then consume its nullifier (replay prevention). */
    public Map<String, Object> verifySubmittedProof(JsonNode body, String clientIp) {
        long start = System.nanoTime();
        if (body == null || !body.isObject()) {
            throw ApiException.badRequest("VALIDATION_ERROR", "Invalid request payload");
        }
        JsonNode proof = body.get("proof");
        if (proof == null || !proof.isObject()) {
            throw ApiException.badRequest("VALIDATION_ERROR", "Missing or invalid 'proof' object in request body");
        }
        JsonNode sig = body.get("publicSignals");
        if (sig == null || !sig.isArray()) {
            throw ApiException.badRequest("VALIDATION_ERROR", "Missing or invalid 'publicSignals' array in request body");
        }
        List<String> signals = new ArrayList<>();
        for (int i = 0; i < sig.size(); i++) {
            if (!sig.get(i).isTextual()) {
                throw ApiException.badRequest("VALIDATION_ERROR", "publicSignals[" + i + "] must be a string");
            }
            signals.add(sig.get(i).asText());
        }
        for (String f : PLONK_FIELDS) {
            if (!proof.hasNonNull(f)) {
                throw ApiException.badRequest("VALIDATION_ERROR", "Proof object missing required PLONK field: '" + f + "'");
            }
        }
        String type = body.hasNonNull("proofType") ? body.get("proofType").asText() : "age_check";
        if (!ZkpService.SIGNALS.containsKey(type)) {
            throw ApiException.badRequest("VALIDATION_ERROR",
                    "Unsupported proof type '" + type + "'. Supported: " + String.join(", ", ZkpService.SIGNALS.keySet()));
        }

        Map<String, String> named;
        try {
            named = ProofSignals.named(type, signals);
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("VALIDATION_ERROR", e.getMessage());
        }
        if (!ProofSignals.currentYearPlausible(named)) {
            throw ApiException.badRequest("VALIDATION_ERROR", "currentYear signal does not match the real year");
        }

        if (!zkp.verify(type, proof, signals)) {
            throw new ApiException(400, "INVALID_PROOF", "Cryptographic proof verification failed");
        }

        String nullifier = named.get("nullifierHash");
        nullifiers.register(nullifier, type, null); // 400 if zero, 409 if replayed

        boolean eligible = "1".equals(named.getOrDefault("isEligible", named.get("inRange")));
        log.info("verification type={} eligible={} ipHash={} ms={}", type, eligible,
                Hashing.sha256Hex(clientIp == null ? "unknown" : clientIp).substring(0, 16),
                (System.nanoTime() - start) / 1_000_000);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("verified", true);
        out.put("isEligible", eligible);
        out.put("proofType", type);
        out.put("nullifierUsed", true);
        out.put("signals", named);
        return out;
    }

    /**
     * GET /v3/verify/:token. Never trusts stored flags: the link and credential must be live, the stored
     * proof is re-verified cryptographically, and its public signals must be bound to this credential.
     */
    public Map<String, Object> verifyShare(String token) {
        ShareLinkEntity share = shares.requireUsable(token);
        CredentialEntity c = credentials.find(share.getCredentialId())
                .orElseThrow(() -> ApiException.notFound("CREDENTIAL_NOT_FOUND",
                        "The credential associated with this link no longer exists."));
        if ("revoked".equals(c.getStatus())) {
            throw new ApiException(410, "CREDENTIAL_REVOKED", "This credential has been revoked by the owner.");
        }
        if (c.getExpiresAt().isBefore(Instant.now())) {
            throw new ApiException(410, "CREDENTIAL_EXPIRED", "This credential has expired.");
        }
        if (c.getProofJson() == null || c.getPublicSignalsJson() == null) {
            throw new ApiException(422, "NO_PROOF", "This credential has no zero-knowledge proof to verify.");
        }

        JsonNode proof;
        List<String> signals;
        Map<String, String> named;
        try {
            proof = mapper.readTree(c.getProofJson());
            signals = mapper.readValue(c.getPublicSignalsJson(), mapper.getTypeFactory().constructCollectionType(List.class, String.class));
            named = ProofSignals.named(CredentialService.CIRCUIT, signals);
        } catch (JsonProcessingException | IllegalArgumentException e) {
            throw new ApiException(422, "INVALID_PROOF", "Stored proof is malformed.");
        }

        if (!zkp.verify(CredentialService.CIRCUIT, proof, signals)) {
            throw new ApiException(422, "INVALID_PROOF", "The credential's proof failed cryptographic verification.");
        }
        boolean bound = named.get("externalNullifier").equals(Hashing.deriveExternalNullifier(c.getId()))
                && named.get("nullifierHash").equals(c.getNullifierHash())
                && named.get("ageLimit").equals(String.valueOf(CredentialService.AGE_LIMIT))
                && named.get("currentYear").equals(String.valueOf(c.getIssuedYear()));
        if (!bound) {
            throw new ApiException(422, "PROOF_MISMATCH", "The proof is not bound to this credential.");
        }
        NullifierEntity n = nullifiers.find(c.getNullifierHash()).orElse(null);
        if (n == null || !c.getId().equals(n.getCredentialId())) {
            throw new ApiException(409, "NULLIFIER_MISMATCH", "The credential's nullifier is not registered to it.");
        }

        shares.recordVerification(share);
        boolean eligible = "1".equals(named.get("isEligible"));

        Map<String, Object> zk = new LinkedHashMap<>();
        zk.put("verified", true);
        zk.put("circuit", c.getCircuit());
        zk.put("proofSystem", "PLONK");
        zk.put("curve", "BN128");
        Map<String, Object> binding = new LinkedHashMap<>();
        binding.put("documentHashPrefix", c.getDocumentHash().substring(0, 16) + "...");
        binding.put("bindingMethod", "SHA-256 document binding + PLONK proof");

        Map<String, Object> v = new LinkedHashMap<>();
        v.put("verified", true);
        v.put("eligible", eligible);
        v.put("isEligible", eligible);
        v.put("proofHash", Hashing.sha256Hex(c.getProofJson()));
        v.put("credentialType", c.getCredentialType());
        v.put("zkProof", zk);
        v.put("documentBinding", binding);
        v.put("sharedWith", share.getOrganizationName() == null || share.getOrganizationName().isBlank()
                ? "Public" : share.getOrganizationName());
        v.put("issuedAt", c.getIssuedAt().toString());
        v.put("expiresAt", share.getExpiresAt().toString());
        v.put("verificationCount", share.getVerificationCount());
        v.put("timestamp", c.getIssuedAt().toString());
        return v;
    }
}
