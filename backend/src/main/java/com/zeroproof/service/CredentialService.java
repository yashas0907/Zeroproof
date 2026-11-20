package com.zeroproof.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeroproof.api.ApiException;
import com.zeroproof.crypto.Hashing;
import com.zeroproof.entity.CredentialEntity;
import com.zeroproof.entity.DocumentEntity;
import com.zeroproof.entity.Repositories.CredentialRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDate;
import java.time.Year;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class CredentialService {
    public static final int AGE_LIMIT = 18;
    public static final String CIRCUIT = "age_check";

    private final CredentialRepository creds;
    private final DocumentService documents;
    private final ZkpService zkp;
    private final NullifierService nullifiers;
    private final ObjectMapper mapper = new ObjectMapper();

    public CredentialService(CredentialRepository creds, DocumentService documents, ZkpService zkp, NullifierService nullifiers) {
        this.creds = creds;
        this.documents = documents;
        this.zkp = zkp;
        this.nullifiers = nullifiers;
    }

    public record Overrides(String fullName, String dateOfBirth, String documentType) { }

    public CredentialEntity issue(String documentId, String credentialType, Overrides overrides) {
        DocumentEntity doc = documents.get(documentId);
        String fullName = pick(overrides == null ? null : overrides.fullName(), doc.getFullName());
        String dob = pick(overrides == null ? null : overrides.dateOfBirth(), doc.getDateOfBirth());
        String docType = pick(overrides == null ? null : overrides.documentType(), doc.getDocumentType());

        int currentYear = Year.now().getValue();
        int birthYear = parseBirthYear(dob, currentYear);
        int age = currentYear - birthYear;

        String id = UUID.randomUUID().toString();
        String secret = Hashing.deriveSecret(doc.getDocumentHash(), id);
        String externalNullifier = Hashing.deriveExternalNullifier(id);

        Map<String, Object> inputs = new LinkedHashMap<>();
        inputs.put("birthYear", birthYear);
        inputs.put("currentYear", currentYear);
        inputs.put("ageLimit", AGE_LIMIT);
        inputs.put("secret", secret);
        inputs.put("externalNullifier", externalNullifier);

        ZkpService.ProofResult result = zkp.prove(CIRCUIT, inputs);
        boolean valid = zkp.verify(CIRCUIT, result.proof(), result.publicSignals());
        if (!valid) {
            throw new ApiException(502, "ZKP_FAILED", "Generated proof failed verification");
        }
        Map<String, String> signals = ProofSignals.named(CIRCUIT, result.publicSignals());

        CredentialEntity c = new CredentialEntity();
        c.setId(id);
        c.setDocumentId(doc.getId());
        c.setDocumentHash(doc.getDocumentHash());
        c.setCredentialType(credentialType == null || credentialType.isBlank() ? "age_verification" : credentialType);
        c.setFullName(fullName);
        c.setDateOfBirth(dob);
        c.setDocumentType(docType);
        c.setNameHash(Hashing.sha256Hex(fullName).substring(0, 16));
        try {
            c.setProofJson(mapper.writeValueAsString(result.proof()));
            c.setPublicSignalsJson(mapper.writeValueAsString(result.publicSignals()));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
        c.setProofVerified(true);
        c.setCircuit("age_check_v2");
        c.setNullifierHash(signals.get("nullifierHash"));
        c.setExternalNullifier(externalNullifier);
        c.setIssuedYear(currentYear);
        c.setAttributeHash(Hashing.sha256Hex("{\"birthYear\":" + birthYear + ",\"fullName\":\"" + fullName
                + "\",\"documentType\":\"" + docType + "\"}"));
        Instant now = Instant.now();
        c.setIssuedAt(now);
        c.setExpiresAt(now.plus(365, ChronoUnit.DAYS));
        c.setEligible("1".equals(signals.get("isEligible")));
        c.setAge(age);

        nullifiers.register(c.getNullifierHash(), CIRCUIT, id);
        return creds.save(c);
    }

    private static int parseBirthYear(String dob, int currentYear) {
        int year;
        try {
            year = LocalDate.parse(dob.trim().substring(0, Math.min(10, dob.trim().length()))).getYear();
        } catch (RuntimeException e) {
            throw ApiException.badRequest("INVALID_DATE_OF_BIRTH", "A valid date of birth (YYYY-MM-DD) is required");
        }
        if (year < 1900 || year > currentYear) {
            throw ApiException.badRequest("INVALID_DATE_OF_BIRTH", "Date of birth is out of range");
        }
        return year;
    }

    private static String pick(String preferred, String fallback) {
        if (preferred != null && !preferred.isBlank()) return preferred;
        return fallback == null ? "" : fallback;
    }

    public List<CredentialEntity> list(String documentId) {
        return documentId == null
                ? creds.findByStatusNotOrderByIssuedAtDesc("revoked")
                : creds.findByDocumentIdAndStatusNotOrderByIssuedAtDesc(documentId, "revoked");
    }

    public java.util.Optional<CredentialEntity> find(String id) {
        return creds.findById(id);
    }

    public CredentialEntity get(String id) {
        return creds.findById(id).orElseThrow(() -> ApiException.notFound("CREDENTIAL_NOT_FOUND", "Credential not found"));
    }

    public void revoke(String id) {
        CredentialEntity c = get(id);
        c.setStatus("revoked");
        c.setRevokedAt(Instant.now());
        creds.save(c);
    }
}
