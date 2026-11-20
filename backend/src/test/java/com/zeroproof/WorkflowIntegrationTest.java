package com.zeroproof;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.zeroproof.crypto.DocumentCrypto;
import com.zeroproof.entity.CredentialEntity;
import com.zeroproof.entity.Repositories.CredentialRepository;
import com.zeroproof.entity.Repositories.DocumentRepository;
import com.zeroproof.entity.Repositories.ShareLinkRepository;
import com.zeroproof.entity.ShareLinkEntity;
import com.zeroproof.service.ZkpService;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.Year;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

/** End-to-end tests through the real HTTP layer, H2, and the real snarkjs bridge and circuit artifacts. */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:itest;DB_CLOSE_DELAY=-1",
        "zeroproof.data-dir=target/test-data",
        "zeroproof.keys-dir=../keys",
        "zeroproof.bridge-script=../zkp/zk-bridge.js",
        "zeroproof.tessdata-dir=..",
        "zeroproof.rate-limit=100000"})
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class WorkflowIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ZkpService zkp;
    @Autowired CredentialRepository credRepo;
    @Autowired ShareLinkRepository shareRepo;
    @Autowired DocumentRepository docRepo;
    @Autowired DocumentCrypto crypto;
    private final ObjectMapper om = new ObjectMapper();

    private static String docId;
    private static String credId;
    private static String token;
    private static byte[] pdfBytes;

    private static byte[] makePdf(String... lines) throws Exception {
        try (PDDocument d = new PDDocument(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            PDPage page = new PDPage();
            d.addPage(page);
            try (PDPageContentStream cs = new PDPageContentStream(d, page)) {
                cs.beginText();
                cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                cs.setLeading(16);
                cs.newLineAtOffset(50, 700);
                for (String l : lines) {
                    cs.showText(l);
                    cs.newLine();
                }
                cs.endText();
            }
            d.save(out);
            return out.toByteArray();
        }
    }

    private JsonNode json(MvcResult r) throws Exception {
        return om.readTree(r.getResponse().getContentAsString());
    }

    private JsonNode getJ(String url, int status) throws Exception {
        MvcResult r = mvc.perform(get(url)).andReturn();
        assertEquals(status, r.getResponse().getStatus(), url + " -> " + r.getResponse().getContentAsString());
        return json(r);
    }

    private JsonNode postJ(String url, Object body, int status) throws Exception {
        MvcResult r = mvc.perform(post(url).contentType(MediaType.APPLICATION_JSON).content(om.writeValueAsString(body))).andReturn();
        assertEquals(status, r.getResponse().getStatus(), url + " -> " + r.getResponse().getContentAsString());
        return json(r);
    }

    @Test @Order(1)
    void healthAndUnknownRoute() throws Exception {
        assertEquals("healthy", getJ("/health", 200).get("status").asText());
        JsonNode nf = getJ("/nope", 404);
        assertEquals("NOT_FOUND", nf.at("/error/code").asText());
    }

    @Test @Order(2)
    void uploadRejectsBadInput() throws Exception {
        MvcResult noFile = mvc.perform(multipart("/v3/documents/upload")).andReturn();
        assertEquals(400, noFile.getResponse().getStatus());
        MvcResult txt = mvc.perform(multipart("/v3/documents/upload")
                .file(new MockMultipartFile("document", "a.txt", "text/plain", "hi".getBytes()))).andReturn();
        assertEquals(400, txt.getResponse().getStatus());
        assertEquals("INVALID_FILE_TYPE", json(txt).at("/error/code").asText());
    }

    @Test @Order(3)
    void uploadEncryptsStoresAndExtracts() throws Exception {
        pdfBytes = makePdf("Student Report", "Name: Alice Tester", "DOB: 12/05/1990");
        MvcResult r = mvc.perform(multipart("/v3/documents/upload")
                .file(new MockMultipartFile("document", "id.pdf", "application/pdf", pdfBytes))).andReturn();
        assertEquals(201, r.getResponse().getStatus(), r.getResponse().getContentAsString());
        JsonNode doc = json(r).at("/data/document");
        docId = doc.get("id").asText();
        assertEquals("Alice Tester", doc.at("/attributes/name").asText());
        assertEquals("1990-05-12", doc.at("/attributes/dob").asText());
        assertEquals(com.zeroproof.crypto.Hashing.sha256Hex(pdfBytes), doc.get("documentHash").asText());
        assertFalse(doc.get("duplicate").asBoolean());
        assertFalse(r.getResponse().getContentAsString().contains("vaultPath"));

        // The vault holds ciphertext that decrypts back to the original bytes.
        byte[] blob = Files.readAllBytes(Path.of(docRepo.findById(docId).orElseThrow().getVaultPath()));
        assertFalse(new String(blob, java.nio.charset.StandardCharsets.ISO_8859_1).contains("Alice"));
        assertArrayEquals(pdfBytes, crypto.decrypt(blob));

        // Duplicate upload is detected and returns the same document.
        MvcResult dup = mvc.perform(multipart("/v3/documents/upload")
                .file(new MockMultipartFile("document", "id.pdf", "application/pdf", pdfBytes))).andReturn();
        assertTrue(json(dup).at("/data/document/duplicate").asBoolean());
        assertEquals(docId, json(dup).at("/data/document/id").asText());

        assertEquals(1, getJ("/v3/documents", 200).at("/data/count").asInt());
    }

    @Test @Order(4)
    void issueCredentialGeneratesRealVerifiedProof() throws Exception {
        postJ("/v3/credentials/issue", Map.of(), 400);
        postJ("/v3/credentials/issue", Map.of("documentId", "missing"), 404);
        JsonNode r = postJ("/v3/credentials/issue", Map.of("documentId", docId,
                "overrides", Map.of("fullName", "Alice Tester", "dateOfBirth", "1990-05-12", "documentType", "id_card")), 201);
        JsonNode c = r.at("/data/credential");
        credId = c.get("id").asText();
        assertTrue(c.get("isEligible").asBoolean());
        assertTrue(c.at("/zkProof/verified").asBoolean());
        assertEquals("PLONK", c.at("/zkProof/proofSystem").asText());
        assertEquals(Year.now().getValue() - 1990, c.get("age").asInt());
    }

    @Test @Order(5)
    void minorIsIssuedAsIneligible() throws Exception {
        byte[] other = makePdf("Name: Young Person", "DOB: 01/01/" + (Year.now().getValue() - 10));
        MvcResult up = mvc.perform(multipart("/v3/documents/upload")
                .file(new MockMultipartFile("document", "kid.pdf", "application/pdf", other))).andReturn();
        String id = json(up).at("/data/document/id").asText();
        JsonNode c = postJ("/v3/credentials/issue", Map.of("documentId", id), 201).at("/data/credential");
        assertFalse(c.get("isEligible").asBoolean());
    }

    @Test @Order(6)
    void shareLinkPublicVerificationRechecksProof() throws Exception {
        postJ("/v3/credentials/" + credId + "/share", Map.of("expiresInHours", 0), 400);
        JsonNode s = postJ("/v3/credentials/" + credId + "/share", Map.of("organizationName", "ACME", "expiresInHours", 24), 201);
        token = s.at("/data/shareLink/token").asText();
        assertTrue(token.length() >= 32);

        JsonNode v = getJ("/v3/verify/" + token, 200).at("/data/verification");
        assertTrue(v.get("verified").asBoolean());
        assertTrue(v.get("isEligible").asBoolean());
        assertEquals("ACME", v.get("sharedWith").asText());
        assertEquals(1, v.get("verificationCount").asInt());
        assertFalse(v.toString().contains("Alice"), "no PII in public verification");
        assertEquals(2, getJ("/v3/verify/" + token, 200).at("/data/verification/verificationCount").asInt());

        assertEquals("INVALID_SHARE_LINK", getJ("/v3/verify/not-a-token", 404).at("/error/code").asText());
    }

    @Test @Order(7)
    void expiredShareLinkIsRejected() throws Exception {
        ShareLinkEntity s = new ShareLinkEntity();
        s.setToken("expired-" + UUID.randomUUID());
        s.setCredentialId(credId);
        s.setCreatedAt(Instant.now().minus(2, ChronoUnit.DAYS));
        s.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));
        shareRepo.save(s);
        JsonNode e = getJ("/v3/verify/" + s.getToken(), 404);
        assertEquals("INVALID_SHARE_LINK", e.at("/error/code").asText());
        assertTrue(e.at("/error/message").asText().contains("expired"));
    }

    @Test @Order(8)
    void tamperedOrSwappedStoredProofIsRejectedAtPublicVerification() throws Exception {
        CredentialEntity c = credRepo.findById(credId).orElseThrow();
        String goodProof = c.getProofJson();
        String goodSignals = c.getPublicSignalsJson();

        // flipping the eligibility signal must fail cryptographic verification even though the stored flag says verified
        List<String> sig = om.readValue(goodSignals, om.getTypeFactory().constructCollectionType(List.class, String.class));
        sig.set(0, "0");
        c.setPublicSignalsJson(om.writeValueAsString(sig));
        credRepo.save(c);
        assertEquals("INVALID_PROOF", getJ("/v3/verify/" + token, 422).at("/error/code").asText());

        // corrupted proof element
        c.setPublicSignalsJson(goodSignals);
        ObjectNode p = (ObjectNode) om.readTree(goodProof);
        p.put("eval_a", "12345");
        c.setProofJson(om.writeValueAsString(p));
        credRepo.save(c);
        assertEquals("INVALID_PROOF", getJ("/v3/verify/" + token, 422).at("/error/code").asText());

        // a perfectly valid proof that belongs to a different credential (different external nullifier)
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("birthYear", 1980);
        in.put("currentYear", Year.now().getValue());
        in.put("ageLimit", 18);
        in.put("secret", "424242");
        in.put("externalNullifier", "777");
        ZkpService.ProofResult foreign = zkp.prove("age_check", in);
        c.setProofJson(om.writeValueAsString(foreign.proof()));
        c.setPublicSignalsJson(om.writeValueAsString(foreign.publicSignals()));
        credRepo.save(c);
        assertEquals("PROOF_MISMATCH", getJ("/v3/verify/" + token, 422).at("/error/code").asText());

        c.setProofJson(goodProof);
        c.setPublicSignalsJson(goodSignals);
        credRepo.save(c);
        getJ("/v3/verify/" + token, 200);
    }

    @Test @Order(9)
    void submittedProofsAreVerifiedAndReplayRejected() throws Exception {
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("birthYear", 2000);
        in.put("currentYear", Year.now().getValue());
        in.put("ageLimit", 18);
        in.put("secret", "987654321");
        in.put("externalNullifier", "55555");
        ZkpService.ProofResult pr = zkp.prove("age_check", in);
        Map<String, Object> body = Map.of("proof", pr.proof(), "publicSignals", pr.publicSignals(), "proofType", "age_check");

        // invalid variants are rejected and must NOT consume the nullifier
        List<String> bad = new java.util.ArrayList<>(pr.publicSignals());
        bad.set(0, "0");
        assertEquals("INVALID_PROOF", postJ("/v1/verify",
                Map.of("proof", pr.proof(), "publicSignals", bad, "proofType", "age_check"), 400).at("/error/code").asText());
        ObjectNode corrupt = pr.proof().deepCopy();
        corrupt.put("eval_b", "1");
        assertEquals("INVALID_PROOF", postJ("/v1/verify",
                Map.of("proof", corrupt, "publicSignals", pr.publicSignals()), 400).at("/error/code").asText());

        JsonNode ok = postJ("/v1/verify", body, 200);
        assertTrue(ok.at("/data/verified").asBoolean());
        assertTrue(ok.at("/data/isEligible").asBoolean());
        assertTrue(ok.at("/data/nullifierUsed").asBoolean());

        assertEquals("NULLIFIER_REPLAYED", postJ("/v1/verify", body, 409).at("/error/code").asText());
    }

    @Test @Order(10)
    void malformedVerifyRequestsAreRejected() throws Exception {
        postJ("/v1/verify", Map.of(), 400);
        postJ("/v1/verify", Map.of("proof", Map.of("A", "x"), "publicSignals", List.of("1")), 400);
        postJ("/v1/verify", Map.of("proof", Map.of("A", 1, "B", 1, "C", 1, "Z", 1, "T1", 1, "T2", 1, "T3", 1, "Wxi", 1, "Wxiw", 1),
                "publicSignals", List.of(1, 2, 3, 4, 5)), 400);
        postJ("/v1/verify", Map.of("proof", Map.of("A", 1), "publicSignals", List.of("1"), "proofType", "nope"), 400);
        assertEquals(2, getJ("/v1/proof-types", 200).at("/data/proofTypes").size());
    }

    @Test @Order(11)
    void revokedShareLinkAndWrongCredentialRevocation() throws Exception {
        JsonNode s = postJ("/v3/credentials/" + credId + "/share", Map.of("expiresInHours", 1), 201);
        String t2 = s.at("/data/shareLink/token").asText();
        getJ("/v3/verify/" + t2, 200);

        MvcResult wrong = mvc.perform(delete("/v3/credentials/other-credential/share")
                .contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + t2 + "\"}")).andReturn();
        assertEquals(404, wrong.getResponse().getStatus());
        getJ("/v3/verify/" + t2, 200); // still valid: it could not be revoked through another credential

        MvcResult rev = mvc.perform(delete("/v3/credentials/" + credId + "/share")
                .contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + t2 + "\"}")).andReturn();
        assertEquals(200, rev.getResponse().getStatus());
        assertEquals("INVALID_SHARE_LINK", getJ("/v3/verify/" + t2, 404).at("/error/code").asText());
    }

    @Test @Order(12)
    void revokedCredentialFailsPublicVerification() throws Exception {
        MvcResult r = mvc.perform(delete("/v3/credentials/" + credId)).andReturn();
        assertEquals(200, r.getResponse().getStatus());
        assertEquals("CREDENTIAL_REVOKED", getJ("/v3/verify/" + token, 410).at("/error/code").asText());
        postJ("/v3/credentials/" + credId + "/share", Map.of(), 409);
    }

    @Test @Order(13)
    void documentDeleteRemovesIt() throws Exception {
        MvcResult r = mvc.perform(delete("/v3/documents/" + docId)).andReturn();
        assertEquals(200, r.getResponse().getStatus());
        getJ("/v3/documents/" + docId, 404);
    }
}
