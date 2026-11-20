package com.zeroproof;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeroproof.crypto.DocumentCrypto;
import com.zeroproof.crypto.Hashing;
import com.zeroproof.entity.Repositories.DocumentRepository;
import com.zeroproof.service.CredentialService;
import com.zeroproof.service.LegacyImporter;
import com.zeroproof.service.ZkpService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.Year;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:security;DB_CLOSE_DELAY=-1",
        "zeroproof.data-dir=target/test-data-security",
        "zeroproof.keys-dir=../keys",
        "zeroproof.bridge-script=../zkp/zk-bridge.js",
        "zeroproof.tessdata-dir=..",
        "zeroproof.rate-limit=100000"})
@AutoConfigureMockMvc
class SecurityIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ZkpService zkp;
    @Autowired DocumentCrypto crypto;
    @Autowired DocumentRepository docRepo;
    @Autowired LegacyImporter importer;
    private final ObjectMapper om = new ObjectMapper();

    private MvcResult postJson(String url, Object body) throws Exception {
        return mvc.perform(post(url).contentType(MediaType.APPLICATION_JSON).content(om.writeValueAsString(body))).andReturn();
    }

    private JsonNode body(MvcResult r) throws Exception {
        return om.readTree(r.getResponse().getContentAsString());
    }

    private Map<String, Object> ageInputs(String secret, String ext) {
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("birthYear", 1995);
        in.put("currentYear", Year.now().getValue());
        in.put("ageLimit", 18);
        in.put("secret", secret);
        in.put("externalNullifier", ext);
        return in;
    }

    @Test
    void concurrentReplayOfSameProofAcceptsExactlyOne() throws Exception {
        ZkpService.ProofResult pr = zkp.prove("age_check", ageInputs("1122334455", "9090"));
        String payload = om.writeValueAsString(Map.of("proof", pr.proof(), "publicSignals", pr.publicSignals()));
        int n = 6;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> results = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            results.add(pool.submit(() -> {
                start.await();
                return mvc.perform(post("/v1/verify").contentType(MediaType.APPLICATION_JSON).content(payload))
                        .andReturn().getResponse().getStatus();
            }));
        }
        start.countDown();
        int ok = 0, replay = 0;
        for (Future<Integer> f : results) {
            int s = f.get();
            if (s == 200) ok++;
            else if (s == 409) replay++;
            else fail("unexpected status " + s);
        }
        pool.shutdown();
        assertEquals(1, ok, "exactly one concurrent submission may succeed");
        assertEquals(n - 1, replay);
    }

    @Test
    void rangeCheckProofVerifiesAndWrongSignalCountIsRejected() throws Exception {
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("birthYear", 1990);
        in.put("currentYear", Year.now().getValue());
        in.put("minAge", 21);
        in.put("maxAge", 65);
        in.put("secret", "5566778899");
        in.put("externalNullifier", "31337");
        ZkpService.ProofResult pr = zkp.prove("range_check", in);
        MvcResult ok = postJson("/v1/verify", Map.of("proof", pr.proof(), "publicSignals", pr.publicSignals(), "proofType", "range_check"));
        assertEquals(200, ok.getResponse().getStatus(), ok.getResponse().getContentAsString());
        assertTrue(body(ok).at("/data/isEligible").asBoolean());

        // range_check proof presented as age_check: wrong signal count
        MvcResult wrongType = postJson("/v1/verify", Map.of("proof", pr.proof(), "publicSignals", pr.publicSignals(), "proofType", "age_check"));
        assertEquals(400, wrongType.getResponse().getStatus());
        assertEquals("VALIDATION_ERROR", body(wrongType).at("/error/code").asText());

        // stale currentYear signal is rejected before verification
        List<String> stale = new ArrayList<>(pr.publicSignals());
        stale.set(2, "2001");
        MvcResult old = postJson("/v1/verify", Map.of("proof", pr.proof(), "publicSignals", stale, "proofType", "range_check"));
        assertEquals(400, old.getResponse().getStatus());
    }

    @Test
    void impossibleBirthYearCannotYieldEligibility() {
        // A future birth year still produces a valid proof, but it must report "not eligible".
        Map<String, Object> in = ageInputs("1", "2");
        in.put("birthYear", Year.now().getValue() + 50);
        ZkpService.ProofResult pr = zkp.prove("age_check", in);
        assertEquals("0", pr.publicSignals().get(0));
        assertTrue(zkp.verify("age_check", pr.proof(), pr.publicSignals()));

        // Missing required inputs are rejected by the circuit as input errors, not server faults.
        var ex = assertThrows(com.zeroproof.api.ApiException.class, () -> zkp.prove("age_check", Map.of("birthYear", 1990)));
        assertEquals("INVALID_CIRCUIT_INPUT", ex.code());
    }

    @Test
    void documentDownloadDecryptsAndDetectsTampering() throws Exception {
        byte[] png = Files.readAllBytes(Path.of("../web/public/vite.svg"));
        MvcResult up = mvc.perform(multipart("/v3/documents/upload")
                .file(new MockMultipartFile("document", "x.png", "image/png", (UUID.randomUUID() + new String(png)).getBytes()))).andReturn();
        assertEquals(201, up.getResponse().getStatus());
        String id = body(up).at("/data/document/id").asText();

        MvcResult file = mvc.perform(get("/v3/documents/" + id + "/file")).andReturn();
        assertEquals(200, file.getResponse().getStatus());
        assertEquals(body(up).at("/data/document/documentHash").asText(), Hashing.sha256Hex(file.getResponse().getContentAsByteArray()));
        assertEquals("no-store", file.getResponse().getHeader("Cache-Control"));

        Path vault = Path.of(docRepo.findById(id).orElseThrow().getVaultPath());
        byte[] blob = Files.readAllBytes(vault);
        blob[blob.length - 1] ^= 1;
        Files.write(vault, blob);
        MvcResult tampered = mvc.perform(get("/v3/documents/" + id + "/file")).andReturn();
        assertEquals(409, tampered.getResponse().getStatus());
        assertEquals("DOCUMENT_UNREADABLE", body(tampered).at("/error/code").asText());
    }

    @Test
    void legacyImportRevalidatesProofsAndNeverTouchesSources(@TempDir Path legacy) throws Exception {
        int year = Year.now().getValue();
        // three legacy documents: decryptable with current key, encrypted with a lost key, missing file
        byte[] plainA = "legacy document A".getBytes(StandardCharsets.UTF_8);
        String docA = UUID.randomUUID().toString(), docB = UUID.randomUUID().toString(), docC = UUID.randomUUID().toString();
        Files.createDirectories(legacy.resolve("vault"));
        Files.write(legacy.resolve("vault").resolve("vault_" + docA + ".enc"), crypto.encrypt(plainA));
        byte[] otherKey = new byte[32];
        new SecureRandom().nextBytes(otherKey);
        Files.write(legacy.resolve("vault").resolve("vault_" + docB + ".enc"), new DocumentCrypto(otherKey).encrypt("B".getBytes()));

        // credential 1: proof produced exactly as the legacy Node issuer did
        String cred1 = UUID.randomUUID().toString();
        String hashA = Hashing.sha256Hex(plainA);
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("birthYear", 1990);
        in.put("currentYear", year);
        in.put("ageLimit", 18);
        in.put("secret", Hashing.deriveSecret(hashA, cred1));
        in.put("externalNullifier", Hashing.deriveExternalNullifier(cred1));
        ZkpService.ProofResult good = zkp.prove("age_check", in);
        // credential 2: tampered public signals
        String cred2 = UUID.randomUUID().toString();
        List<String> badSignals = new ArrayList<>(good.publicSignals());
        badSignals.set(0, "0");
        // credential 3: no proof
        String cred3 = UUID.randomUUID().toString();

        Instant now = Instant.now();
        Map<String, Object> db = Map.of(
                "docs", List.of(
                        legacyDoc(docA, hashA), legacyDoc(docB, Hashing.sha256Hex("B".getBytes())), legacyDoc(docC, "00")),
                "creds", List.of(
                        legacyCred(cred1, docA, hashA, Map.of("proof", good.proof(), "publicSignals", good.publicSignals(), "verified", true), now),
                        legacyCred(cred2, docA, hashA, Map.of("proof", good.proof(), "publicSignals", badSignals, "verified", true), now),
                        legacyCred(cred3, docA, hashA, null, now)));
        String tok1 = "legacy-" + UUID.randomUUID(), tok2 = "legacy-" + UUID.randomUUID();
        List<Map<String, Object>> sharesJson = List.of(legacyShare(tok1, cred1, now), legacyShare(tok2, cred2, now));
        Files.writeString(legacy.resolve("dynamodb_mock.json"), om.writeValueAsString(db));
        Files.writeString(legacy.resolve("shares.json"), om.writeValueAsString(sharesJson));
        String before = Hashing.sha256Hex(Files.readAllBytes(legacy.resolve("dynamodb_mock.json")))
                + Hashing.sha256Hex(Files.readAllBytes(legacy.resolve("shares.json")))
                + Hashing.sha256Hex(Files.readAllBytes(legacy.resolve("vault").resolve("vault_" + docB + ".enc")));

        Path report = legacy.resolve("out").resolve("report.json");
        LegacyImporter.Report r = importer.importFrom(legacy, report);
        assertEquals(3, r.documentsImported);
        assertEquals(1, r.documentsDecryptable);
        assertEquals(1, r.documentsUndecryptable);
        assertEquals(1, r.documentsMissingFile);
        assertEquals(3, r.credentialsImported);
        assertEquals(1, r.proofsVerified);
        assertEquals(1, r.proofsUnverifiable);
        assertEquals(List.of(cred2), r.unverifiableCredentialIds);
        assertEquals(1, r.credentialsWithoutProof);
        assertEquals(2, r.shareLinksImported);
        assertTrue(Files.exists(report));
        assertFalse(Files.readString(report).contains("Legacy Person"), "report contains no personal data");

        // legacy credential + share link verify publicly with the Java backend (derivation compatibility)
        MvcResult v1 = mvc.perform(get("/v3/verify/" + tok1)).andReturn();
        assertEquals(200, v1.getResponse().getStatus(), v1.getResponse().getContentAsString());
        MvcResult v2 = mvc.perform(get("/v3/verify/" + tok2)).andReturn();
        assertEquals(422, v2.getResponse().getStatus());
        // decryptable legacy document can be downloaded; undecryptable one reports why
        assertEquals(200, mvc.perform(get("/v3/documents/" + docA + "/file")).andReturn().getResponse().getStatus());
        assertEquals(409, mvc.perform(get("/v3/documents/" + docB + "/file")).andReturn().getResponse().getStatus());
        // deleting an imported document never deletes the legacy vault file
        assertEquals(200, mvc.perform(delete("/v3/documents/" + docB)).andReturn().getResponse().getStatus());

        String after = Hashing.sha256Hex(Files.readAllBytes(legacy.resolve("dynamodb_mock.json")))
                + Hashing.sha256Hex(Files.readAllBytes(legacy.resolve("shares.json")))
                + Hashing.sha256Hex(Files.readAllBytes(legacy.resolve("vault").resolve("vault_" + docB + ".enc")));
        assertEquals(before, after, "legacy sources and vault files are untouched");

        LegacyImporter.Report again = importer.importFrom(legacy, report);
        assertEquals(0, again.documentsImported + again.credentialsImported + again.shareLinksImported);
        assertEquals(8, again.skippedExisting);
    }

    private static Map<String, Object> legacyDoc(String id, String hash) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("originalName", "legacy.pdf");
        m.put("mimeType", "application/pdf");
        m.put("sizeBytes", 17);
        m.put("documentHash", hash);
        m.put("attributes", Map.of("fullName", "Legacy Person", "dateOfBirth", "1990-01-01", "documentType", "other"));
        m.put("isVerified", true);
        m.put("createdAt", Instant.now().toString());
        m.put("status", "active");
        return m;
    }

    private static Map<String, Object> legacyCred(String id, String docId, String hash, Map<String, Object> zk, Instant issued) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("documentId", docId);
        m.put("documentHash", hash);
        m.put("credentialType", "age_verification");
        m.put("attributes", Map.of("fullName", "Legacy Person", "dateOfBirth", "1990-01-01", "documentType", "other"));
        m.put("zkProof", zk);
        m.put("binding", Map.of("documentHash", hash, "attributeHash", "x"));
        m.put("issuedAt", issued.toString());
        m.put("expiresAt", issued.plus(365, ChronoUnit.DAYS).toString());
        m.put("status", "active");
        m.put("isEligible", true);
        m.put("age", 30);
        return m;
    }

    private static Map<String, Object> legacyShare(String token, String credId, Instant now) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("token", token);
        m.put("credentialId", credId);
        m.put("organizationName", "Legacy Org");
        m.put("createdAt", now.toString());
        m.put("expiresAt", now.plus(1, ChronoUnit.DAYS).toString());
        m.put("status", "active");
        m.put("verificationCount", 3);
        return m;
    }

    @Test
    void credentialIssueRejectsInvalidDateOfBirth() throws Exception {
        MvcResult up = mvc.perform(multipart("/v3/documents/upload")
                .file(new MockMultipartFile("document", "n.png", "image/png", UUID.randomUUID().toString().getBytes()))).andReturn();
        String id = body(up).at("/data/document/id").asText();
        MvcResult r = postJson("/v3/credentials/issue", Map.of("documentId", id,
                "overrides", Map.of("fullName", "A B", "dateOfBirth", "not-a-date")));
        assertEquals(400, r.getResponse().getStatus());
        assertEquals("INVALID_DATE_OF_BIRTH", body(r).at("/error/code").asText());
        MvcResult future = postJson("/v3/credentials/issue", Map.of("documentId", id,
                "overrides", Map.of("fullName", "A B", "dateOfBirth", (Year.now().getValue() + 1) + "-01-01")));
        assertEquals(400, future.getResponse().getStatus());
        assertEquals(CredentialService.AGE_LIMIT, 18);
    }
}
