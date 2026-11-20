package com.zeroproof.controller;

import com.zeroproof.api.ApiException;
import com.zeroproof.api.ApiResponse;
import com.zeroproof.entity.CredentialEntity;
import com.zeroproof.entity.ShareLinkEntity;
import com.zeroproof.service.CredentialService;
import com.zeroproof.service.ShareService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v3/credentials")
public class CredentialController {
    private final CredentialService credentials;
    private final ShareService shares;

    public CredentialController(CredentialService credentials, ShareService shares) {
        this.credentials = credentials;
        this.shares = shares;
    }

    public record IssueRequest(String documentId, String credentialType, Overrides overrides) { }

    public record Overrides(String fullName, String dateOfBirth, String documentType) { }

    public record ShareRequest(Long expiresInHours, String organizationName) { }

    public record RevokeShareRequest(String token) { }

    @PostMapping("/issue")
    public ResponseEntity<Map<String, Object>> issue(@RequestBody IssueRequest req) {
        if (req.documentId() == null || req.documentId().isBlank()) {
            throw ApiException.badRequest("MISSING_DOCUMENT_ID", "documentId is required");
        }
        CredentialService.Overrides o = req.overrides() == null ? null
                : new CredentialService.Overrides(req.overrides().fullName(), req.overrides().dateOfBirth(), req.overrides().documentType());
        CredentialEntity c = credentials.issue(req.documentId(), req.credentialType(), o);
        return ApiResponse.created(Map.of("credential", detail(c, false)), "v3");
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> list(@RequestParam(value = "documentId", required = false) String documentId) {
        List<Map<String, Object>> out = credentials.list(documentId).stream().map(c -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", c.getId());
            m.put("documentId", c.getDocumentId());
            m.put("credentialType", c.getCredentialType());
            m.put("isEligible", c.isEligible());
            m.put("age", c.getAge());
            m.put("hasZkProof", c.getProofJson() != null);
            m.put("zkProofVerified", c.isProofVerified());
            m.put("issuedAt", c.getIssuedAt().toString());
            m.put("expiresAt", c.getExpiresAt().toString());
            m.put("status", c.getStatus());
            m.put("attributes", Map.of("fullName", nz(c.getFullName()), "documentType", nz(c.getDocumentType())));
            return m;
        }).toList();
        return ApiResponse.ok(Map.of("credentials", out, "count", out.size()), "v3");
    }

    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> get(@PathVariable String id) {
        CredentialEntity c = credentials.get(id);
        List<Map<String, Object>> links = shares.listActive(id).stream().map(s -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("token", s.getToken());
            m.put("organizationName", s.getOrganizationName());
            m.put("expiresAt", s.getExpiresAt().toString());
            m.put("verificationCount", s.getVerificationCount());
            m.put("status", s.getStatus());
            return m;
        }).toList();
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("credential", detail(c, true));
        data.put("shareLinks", links);
        return ApiResponse.ok(data, "v3");
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> revoke(@PathVariable String id) {
        credentials.revoke(id);
        return ApiResponse.ok(Map.of("revoked", true, "credentialId", id), "v3");
    }

    @PostMapping("/{id}/share")
    public ResponseEntity<Map<String, Object>> share(@PathVariable String id, @RequestBody(required = false) ShareRequest req) {
        ShareLinkEntity s = shares.create(id, req == null ? null : req.expiresInHours(),
                req == null ? null : req.organizationName());
        Map<String, Object> link = new LinkedHashMap<>();
        link.put("token", s.getToken());
        link.put("verifyUrl", "/verify/" + s.getToken());
        link.put("organizationName", s.getOrganizationName());
        link.put("expiresAt", s.getExpiresAt().toString());
        link.put("status", s.getStatus());
        return ApiResponse.created(Map.of("shareLink", link), "v3");
    }

    @DeleteMapping("/{id}/share")
    public ResponseEntity<Map<String, Object>> revokeShare(@PathVariable String id, @RequestBody(required = false) RevokeShareRequest req) {
        if (req == null || req.token() == null || req.token().isBlank()) {
            throw ApiException.badRequest("MISSING_TOKEN", "Share link token is required");
        }
        shares.revoke(id, req.token());
        return ApiResponse.ok(Map.of("revoked", true, "token", req.token()), "v3");
    }

    private static Map<String, Object> detail(CredentialEntity c, boolean withAttributes) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", c.getId());
        m.put("documentId", c.getDocumentId());
        m.put("credentialType", c.getCredentialType());
        m.put("isEligible", c.isEligible());
        m.put("age", c.getAge());
        if (withAttributes) {
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("fullName", nz(c.getFullName()));
            a.put("dateOfBirth", nz(c.getDateOfBirth()));
            a.put("documentType", nz(c.getDocumentType()));
            a.put("nameHash", nz(c.getNameHash()));
            m.put("attributes", a);
        }
        Map<String, Object> zk = new LinkedHashMap<>();
        zk.put("verified", c.isProofVerified());
        zk.put("circuit", c.getCircuit());
        zk.put("proofSystem", "PLONK");
        zk.put("curve", "BN128");
        m.put("zkProof", c.getProofJson() == null ? null : zk);
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("documentHash", c.getDocumentHash());
        b.put("attributeHash", c.getAttributeHash());
        b.put("method", "SHA-256 document binding + PLONK proof");
        m.put("binding", b);
        m.put("issuedAt", c.getIssuedAt().toString());
        m.put("expiresAt", c.getExpiresAt().toString());
        m.put("status", c.getStatus());
        return m;
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
