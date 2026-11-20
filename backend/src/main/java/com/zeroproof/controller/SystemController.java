package com.zeroproof.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.zeroproof.api.ApiResponse;
import com.zeroproof.service.VerificationService;
import com.zeroproof.service.ZkpService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Health, API info, and the stateless proof-verification endpoints. */
@RestController
public class SystemController {
    private final VerificationService verification;

    public SystemController(VerificationService verification) {
        this.verification = verification;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", "healthy");
        m.put("service", "zeroproof-backend");
        m.put("version", "3.0.0");
        m.put("timestamp", Instant.now().toString());
        return m;
    }

    @GetMapping("/")
    public Map<String, Object> info() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", "ZeroProof Verification API");
        m.put("backend", "Java 21 / Spring Boot");
        m.put("endpoints", List.of("POST /v1/verify", "GET /v1/proof-types",
                "POST /v3/documents/upload", "GET /v3/documents", "POST /v3/credentials/issue",
                "GET /v3/credentials", "POST /v3/credentials/{id}/share", "GET /v3/verify/{token}"));
        return m;
    }

    @PostMapping("/v1/verify")
    public ResponseEntity<Map<String, Object>> verify(@RequestBody JsonNode body, HttpServletRequest req) {
        return ApiResponse.ok(verification.verifySubmittedProof(body, req.getRemoteAddr()), "v1");
    }

    @GetMapping("/v1/proof-types")
    public ResponseEntity<Map<String, Object>> proofTypes() {
        List<Map<String, Object>> types = new ArrayList<>();
        ZkpService.SIGNALS.forEach((name, signals) -> {
            Map<String, Object> t = new LinkedHashMap<>();
            t.put("name", name);
            t.put("publicSignals", signals);
            t.put("signalCount", signals.size());
            types.add(t);
        });
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("proofTypes", types);
        data.put("supported", ZkpService.SIGNALS.keySet().stream().sorted().toList());
        return ApiResponse.ok(data, "v1");
    }
}
