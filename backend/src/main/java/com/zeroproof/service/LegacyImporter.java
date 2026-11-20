package com.zeroproof.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.zeroproof.crypto.DocumentCrypto;
import com.zeroproof.crypto.Hashing;
import com.zeroproof.entity.CredentialEntity;
import com.zeroproof.entity.DocumentEntity;
import com.zeroproof.entity.NullifierEntity;
import com.zeroproof.entity.Repositories.CredentialRepository;
import com.zeroproof.entity.Repositories.DocumentRepository;
import com.zeroproof.entity.Repositories.NullifierRepository;
import com.zeroproof.entity.Repositories.ShareLinkRepository;
import com.zeroproof.entity.ShareLinkEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * One-time, idempotent import of the legacy Node data (dynamodb_mock.json, shares.json).
 * Source files and legacy vault files are only read, never modified or deleted.
 * Every imported proof is re-verified; unverifiable proofs are kept but marked unverified, so
 * public verification rejects them. Results are written to data/java/legacy-import-report.json
 * (ids and counts only, no personal data).
 */
@Service
public class LegacyImporter {
    private static final Logger log = LoggerFactory.getLogger(LegacyImporter.class);

    private final DocumentRepository docs;
    private final CredentialRepository creds;
    private final ShareLinkRepository shares;
    private final NullifierRepository nullifiers;
    private final ZkpService zkp;
    private final DocumentCrypto crypto;
    private final ObjectMapper mapper = new ObjectMapper();

    public LegacyImporter(DocumentRepository docs, CredentialRepository creds, ShareLinkRepository shares,
                          NullifierRepository nullifiers, ZkpService zkp, DocumentCrypto crypto) {
        this.docs = docs;
        this.creds = creds;
        this.shares = shares;
        this.nullifiers = nullifiers;
        this.zkp = zkp;
        this.crypto = crypto;
    }

    public static final class Report {
        public int documentsImported;
        public int documentsDecryptable;
        public int documentsUndecryptable;
        public int documentsMissingFile;
        public int credentialsImported;
        public int proofsVerified;
        public int proofsUnverifiable;
        public int credentialsWithoutProof;
        public int shareLinksImported;
        public int skippedExisting;
        public List<String> unverifiableCredentialIds = new ArrayList<>();
        public List<String> undecryptableDocumentIds = new ArrayList<>();
        public String finishedAt;
    }

    /** Imports from {@code legacyDir} and writes the report to {@code reportFile}. */
    public Report importFrom(Path legacyDir, Path reportFile) throws IOException {
        Report r = new Report();
        Path db = legacyDir.resolve("dynamodb_mock.json");
        if (Files.isRegularFile(db)) {
            JsonNode root = mapper.readTree(Files.readString(db));
            for (JsonNode n : root.path("docs")) {
                importDocument(n, legacyDir, r);
            }
            for (JsonNode n : root.path("creds")) {
                importCredential(n, r);
            }
        }
        Path sh = legacyDir.resolve("shares.json");
        if (Files.isRegularFile(sh)) {
            for (JsonNode n : mapper.readTree(Files.readString(sh))) {
                importShare(n, r);
            }
        }
        r.finishedAt = Instant.now().toString();
        Files.createDirectories(reportFile.toAbsolutePath().getParent());
        mapper.copy().enable(SerializationFeature.INDENT_OUTPUT).writeValue(reportFile.toFile(), r);
        log.info("Legacy import: docs={} (decryptable={}, undecryptable={}, missingFile={}), credentials={} "
                        + "(proofsVerified={}, unverifiable={}, noProof={}), shares={}, skippedExisting={}. Report: {}",
                r.documentsImported, r.documentsDecryptable, r.documentsUndecryptable, r.documentsMissingFile,
                r.credentialsImported, r.proofsVerified, r.proofsUnverifiable, r.credentialsWithoutProof,
                r.shareLinksImported, r.skippedExisting, reportFile.toAbsolutePath());
        return r;
    }

    private void importDocument(JsonNode n, Path legacyDir, Report r) {
        String id = n.path("id").asText("");
        if (id.isEmpty()) return;
        if (docs.existsById(id)) {
            r.skippedExisting++;
            return;
        }
        DocumentEntity e = new DocumentEntity();
        e.setId(id);
        e.setOriginalName(n.path("originalName").asText("document"));
        e.setMimeType(n.path("mimeType").asText("application/octet-stream"));
        e.setSizeBytes(n.path("sizeBytes").asLong());
        e.setDocumentHash(n.path("documentHash").asText(""));
        JsonNode a = n.path("attributes");
        e.setFullName(text(a, "fullName", text(a, "name", "")));
        e.setDateOfBirth(text(a, "dateOfBirth", text(a, "dob", "")));
        e.setDocumentType(text(a, "documentType", "other"));
        e.setExtractStatus(text(a, "status", "SUCCESS"));
        e.setReason(a.hasNonNull("reason") ? a.get("reason").asText() : null);
        e.setVerified(n.path("isVerified").asBoolean());
        e.setStatus(n.path("status").asText("active"));
        e.setCreatedAt(parse(n.path("createdAt").asText(), Instant.now()));

        // Legacy layout: vaultPath "vault/<id>.enc" was stored on disk as data/vault/vault_<id>.enc
        Path legacyFile = legacyDir.resolve("vault").resolve("vault_" + id + ".enc");
        e.setVaultPath(legacyFile.toString());
        if (!Files.isRegularFile(legacyFile)) {
            r.documentsMissingFile++;
            e.setImportNote("legacy import: encrypted file not found");
        } else {
            try {
                byte[] plain = crypto.decrypt(Files.readAllBytes(legacyFile));
                if (Hashing.sha256Hex(plain).equals(e.getDocumentHash())) {
                    r.documentsDecryptable++;
                    e.setImportNote("legacy import: decryptable with the configured key");
                } else {
                    r.documentsUndecryptable++;
                    r.undecryptableDocumentIds.add(id);
                    e.setImportNote("legacy import: decrypted content does not match stored hash");
                }
            } catch (Exception ex) {
                r.documentsUndecryptable++;
                r.undecryptableDocumentIds.add(id);
                e.setImportNote("legacy import: not decryptable with the configured key");
            }
        }
        docs.save(e);
        r.documentsImported++;
    }

    private void importCredential(JsonNode n, Report r) {
        String id = n.path("id").asText("");
        if (id.isEmpty()) return;
        if (creds.existsById(id)) {
            r.skippedExisting++;
            return;
        }
        CredentialEntity e = new CredentialEntity();
        e.setId(id);
        e.setDocumentId(n.path("documentId").asText(""));
        e.setDocumentHash(n.path("documentHash").asText(""));
        e.setCredentialType(n.path("credentialType").asText("age_verification"));
        JsonNode a = n.path("attributes");
        e.setFullName(text(a, "fullName", ""));
        e.setDateOfBirth(text(a, "dateOfBirth", ""));
        e.setDocumentType(text(a, "documentType", ""));
        e.setNameHash(text(a, "nameHash", ""));
        e.setAttributeHash(n.path("binding").path("attributeHash").asText(""));
        Instant issued = parse(n.path("issuedAt").asText(), Instant.now());
        e.setIssuedAt(issued);
        e.setExpiresAt(parse(n.path("expiresAt").asText(), issued.plus(365, ChronoUnit.DAYS)));
        e.setIssuedYear(issued.atZone(ZoneOffset.UTC).getYear());
        e.setStatus(n.path("status").asText("active"));
        e.setEligible(n.path("isEligible").asBoolean());
        e.setAge(n.path("age").asInt());
        e.setCircuit("age_check_v2");
        e.setExternalNullifier(Hashing.deriveExternalNullifier(id));

        JsonNode zk = n.path("zkProof");
        if (zk.hasNonNull("proof") && zk.path("publicSignals").isArray()) {
            List<String> signals = new ArrayList<>();
            zk.get("publicSignals").forEach(x -> signals.add(x.asText()));
            e.setProofJson(zk.get("proof").toString());
            try {
                e.setPublicSignalsJson(mapper.writeValueAsString(signals));
            } catch (IOException ex) {
                throw new IllegalStateException(ex);
            }
            boolean ok = false;
            try {
                ok = signals.size() == ZkpService.SIGNALS.get(CredentialService.CIRCUIT).size()
                        && zkp.verify(CredentialService.CIRCUIT, zk.get("proof"), signals);
            } catch (RuntimeException ex) {
                log.warn("Could not re-verify legacy proof for credential {}: {}", id, ex.getMessage());
            }
            if (ok) {
                Map<String, String> named = ProofSignals.named(CredentialService.CIRCUIT, signals);
                e.setNullifierHash(named.get("nullifierHash"));
                e.setEligible("1".equals(named.get("isEligible")));
                if (!nullifiers.existsById(named.get("nullifierHash"))) {
                    nullifiers.saveAndFlush(new NullifierEntity(named.get("nullifierHash"), CredentialService.CIRCUIT, id));
                    e.setProofVerified(true);
                    e.setImportNote("legacy import: proof re-verified");
                    r.proofsVerified++;
                } else {
                    e.setImportNote("legacy import: proof valid but nullifier already registered to another record");
                    r.proofsUnverifiable++;
                    r.unverifiableCredentialIds.add(id);
                }
            } else {
                e.setProofVerified(false);
                e.setImportNote("legacy import: proof failed re-verification");
                r.proofsUnverifiable++;
                r.unverifiableCredentialIds.add(id);
            }
        } else {
            e.setImportNote("legacy import: no proof");
            r.credentialsWithoutProof++;
        }
        creds.save(e);
        r.credentialsImported++;
    }

    private void importShare(JsonNode n, Report r) {
        String token = n.path("token").asText("");
        if (token.isEmpty()) return;
        if (shares.existsById(token)) {
            r.skippedExisting++;
            return;
        }
        ShareLinkEntity e = new ShareLinkEntity();
        e.setToken(token);
        e.setCredentialId(n.path("credentialId").asText(""));
        e.setOrganizationName(n.path("organizationName").asText(""));
        Instant created = parse(n.path("createdAt").asText(), Instant.now());
        e.setCreatedAt(created);
        e.setExpiresAt(parse(n.path("expiresAt").asText(), created));
        e.setStatus(n.path("status").asText("active"));
        e.setVerificationCount(n.path("verificationCount").asInt());
        if (n.hasNonNull("lastVerifiedAt")) e.setLastVerifiedAt(parse(n.get("lastVerifiedAt").asText(), null));
        if (n.hasNonNull("revokedAt")) e.setRevokedAt(parse(n.get("revokedAt").asText(), null));
        shares.save(e);
        r.shareLinksImported++;
    }

    private static String text(JsonNode n, String field, String fallback) {
        JsonNode v = n.get(field);
        return v == null || v.isNull() || v.asText().isEmpty() ? fallback : v.asText();
    }

    private static Instant parse(String iso, Instant fallback) {
        try {
            return Instant.parse(iso);
        } catch (RuntimeException e) {
            return fallback;
        }
    }
}
