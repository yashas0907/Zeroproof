package com.zeroproof.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/** Builds the {status, data, meta, error} envelope the frontend already consumes. */
public final class ApiResponse {
    private ApiResponse() { }

    public static ResponseEntity<Map<String, Object>> ok(Object data, String version) {
        return build(HttpStatus.OK, data, version);
    }

    public static ResponseEntity<Map<String, Object>> created(Object data, String version) {
        return build(HttpStatus.CREATED, data, version);
    }

    private static ResponseEntity<Map<String, Object>> build(HttpStatus status, Object data, String version) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "success");
        body.put("data", data);
        body.put("meta", meta(version));
        body.put("error", null);
        return ResponseEntity.status(status).body(body);
    }

    public static ResponseEntity<Map<String, Object>> error(int status, String code, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "error");
        body.put("data", null);
        body.put("meta", meta("v1"));
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("code", code);
        err.put("message", message);
        body.put("error", err);
        return ResponseEntity.status(status).body(body);
    }

    private static Map<String, Object> meta(String version) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("requestId", UUID.randomUUID().toString());
        m.put("version", version);
        m.put("timestamp", Instant.now().toString());
        return m;
    }
}
