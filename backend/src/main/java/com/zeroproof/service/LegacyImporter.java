package com.zeroproof.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeroproof.config.AppProperties;
import com.zeroproof.crypto.DocumentCrypto;
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
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Opt-in one-time import of the legacy Node data (data/dynamodb_mock.json, data/shares.json).
 * Enable with ZEROPROOF_IMPORT_LEGACY=true. Source files are only read, never modified.
 * Imported proofs are re-verified; documents are checked for decryptability with the current key.
 */
@Component
@ConditionalOnProperty(name = "zeroproof.import-legacy", havingValue = "true")
public class LegacyImporter implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(LegacyImporter.class);

    private final AppProperties props;
    private final DocumentRepository docs;
    private final CredentialRepository creds;
    private final ShareLinkRepository shares;
    private final NullifierRepository nullifiers;
    private final ZkpService zkp;
    private final DocumentCrypto crypto;
    private final ObjectMapper mapper = new ObjectMapper();

    public LegacyImporter(AppProperties props, DocumentRepository docs, CredentialRepository creds,
                          ShareLinkRepository shares, NullifierRepository nullifiers, ZkpService zkp, DocumentCrypto crypto) {
        this.props = props;
        this.docs = docs;
        this.creds = creds;
        this.shares = shares;
        this.nullifiers = nullifiers;
        this.zkp = zkp;
        this.crypto = crypto;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Path dir = Path.of(props.dataDir());
        Path db = dir.resolve("dynamodb_mock.json");
        int d = 0, decryptable = 0, c = 0, verified = 0, s = 0;
        if (Files.exists(db)) {
            JsonNode root = mapper.readTree(Files.readString(db));
            for (JsonNode n : root.path("docs")) {
                if (docs.existsById(n.path("id").asText())) continue;
                DocumentEntity e = new DocumentEntity();
                e.setId(n.path("id").asText());
                e.setOriginalName(n.path("originalName").asText());
                e.setMimeType(n.path("mimeType").asText());
                e.setSizeBytes(n.path("sizeBytes").asLong());
                e.setDocumentHash(n.path("documentHash").asText());
                JsonNode a = n.path("attributes");
                e.setFullName(a.path("fullName").asText(""));
                e.setDateOfBirth(a.path("dateOfBirth").asText(""));
                e.setDocumentType(a.path("documentType").asText("other"));
                e.setExtractStatus(a.path("status").asText("SUCCESS"));
                e.setReason(a.path("reason").isNull() ? null : a.path("reason").asText(null));
                e.setVerified(n.path("isVerified").asBoolean());
                Path legacyFile = dir.resolve("vault").resolve("vault_" + e.getId() + ".enc");
                e.setVaultPath(legacyFile.toString());
                e.setStatus(n.path("status").asText("active"));
                e.setCreatedAt(parse(n.path("createdAt").asText()));
                docs.save(e);
                d++;
                if (Files.exists(legacyFile)) {
                    try {
                        crypto.decrypt(Files.readAllBytes(legacyFile));
                        decryptable++;
                    } catch (Exception ignored) {
                        // encrypted with a key that is not the current one
                    }
                }
            }
            for (JsonNode n : root.path("creds")) {
                String id = n.path("id").asText();
                if (creds.existsById(id)) continue;
                CredentialEntity e = new CredentialEntity();
                e.setId(id);
                e.setDocumentId(n.path("documentId").asText());
                e.setDocumentHash(n.path("documentHash").asText());
                e.setCredentialType(n.path("credentialType").asText("age_verification"));
                JsonNode a = n.path("attributes");
                e.setFullName(a.path("fullName").asText(""));
                e.setDateOfBirth(a.path("dateOfBirth").asText(""));
                e.setDocumentType(a.path("documentType").asText(""));
                e.setNameHash(a.path("nameHash").asText(""));
                e.setAttributeHash(n.path("binding").path("attributeHash").asText(""));
                e.setIssuedAt(parse(n.path("issuedAt").asText()));
                e.setExpiresAt(parse(n.path("expiresAt").asText()));
                e.setIssuedYear(e.getIssuedAt().atZone(java.time.ZoneOffset.UTC).getYear());
                e.setStatus(n.path("status").asText("active"));
                e.setEligible(n.path("isEligible").asBoolean());
                e.setAge(n.path("age").asInt());
                e.setCircuit("age_check_v2");
                e.setExternalNullifier(com.zeroproof.crypto.Hashing.deriveExternalNullifier(id));
                JsonNode zk = n.path("zkProof");
                if (zk.hasNonNull("proof") && zk.hasNonNull("publicSignals")) {
                    List<String> signals = new ArrayList<>();
                    zk.get("publicSignals").forEach(x -> signals.add(x.asText()));
                    boolean ok = false;
                    try {
                        ok = signals.size() == 5 && zkp.verify(CredentialService.CIRCUIT, zk.get("proof"), signals);
                    } catch (RuntimeException ex) {
                        log.warn("Could not re-verify legacy proof for {}", id);
                    }
                    if (ok) {
                        e.setProofJson(zk.get("proof").toString());
                        e.setPublicSignalsJson(mapper.writeValueAsString(signals));
                        e.setProofVerified(true);
                        e.setNullifierHash(signals.get(1));
                        if (!nullifiers.existsById(signals.get(1))) {
                            nullifiers.saveAndFlush(new NullifierEntity(signals.get(1), CredentialService.CIRCUIT, id));
                        }
                        verified++;
                    }
                }
                creds.save(e);
                c++;
            }
        }
        Path sh = dir.resolve("shares.json");
        if (Files.exists(sh)) {
            for (JsonNode n : mapper.readTree(Files.readString(sh))) {
                String token = n.path("token").asText();
                if (shares.existsById(token)) continue;
                ShareLinkEntity e = new ShareLinkEntity();
                e.setToken(token);
                e.setCredentialId(n.path("credentialId").asText());
                e.setOrganizationName(n.path("organizationName").asText(""));
                e.setCreatedAt(parse(n.path("createdAt").asText()));
                e.setExpiresAt(parse(n.path("expiresAt").asText()));
                e.setStatus(n.path("status").asText("active"));
                e.setVerificationCount(n.path("verificationCount").asInt());
                shares.save(e);
                s++;
            }
        }
        log.info("Legacy import: {} documents ({} decryptable with current key), {} credentials ({} proofs re-verified), {} share links",
                d, decryptable, c, verified, s);
    }

    private static Instant parse(String iso) {
        try {
            return Instant.parse(iso);
        } catch (RuntimeException e) {
            return Instant.now();
        }
    }
}
