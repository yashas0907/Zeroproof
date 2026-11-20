package com.zeroproof.controller;

import com.zeroproof.api.ApiResponse;
import com.zeroproof.service.VerificationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/v3/verify")
public class PublicVerifyController {
    private final VerificationService verification;

    public PublicVerifyController(VerificationService verification) {
        this.verification = verification;
    }

    @GetMapping("/{token}")
    public ResponseEntity<Map<String, Object>> verify(@PathVariable String token) {
        return ApiResponse.ok(Map.of("verification", verification.verifyShare(token)), "v3");
    }
}
