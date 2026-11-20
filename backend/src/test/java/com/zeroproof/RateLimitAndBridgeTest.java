package com.zeroproof;

import com.zeroproof.api.ApiException;
import com.zeroproof.config.AppProperties;
import com.zeroproof.service.ZkpService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:ratelimit;DB_CLOSE_DELAY=-1",
        "zeroproof.data-dir=target/test-data-ratelimit",
        "zeroproof.rate-limit=3"})
@AutoConfigureMockMvc
class RateLimitAndBridgeTest {
    @Autowired MockMvc mvc;

    @Test
    void requestsBeyondTheLimitGet429WithHeaders() throws Exception {
        for (int i = 1; i <= 3; i++) {
            MvcResult r = mvc.perform(get("/health").with(req -> { req.setRemoteAddr("10.0.0.9"); return req; })).andReturn();
            assertEquals(200, r.getResponse().getStatus());
            assertEquals("3", r.getResponse().getHeader("X-RateLimit-Limit"));
            assertEquals(String.valueOf(3 - i), r.getResponse().getHeader("X-RateLimit-Remaining"));
        }
        MvcResult limited = mvc.perform(get("/health").with(req -> { req.setRemoteAddr("10.0.0.9"); return req; })).andReturn();
        assertEquals(429, limited.getResponse().getStatus());
        assertNotNull(limited.getResponse().getHeader("Retry-After"));
        assertTrue(limited.getResponse().getContentAsString().contains("RATE_LIMITED"));

        // a different client is unaffected
        MvcResult other = mvc.perform(get("/health").with(req -> { req.setRemoteAddr("10.0.0.10"); return req; })).andReturn();
        assertEquals(200, other.getResponse().getStatus());
    }

    private static AppProperties props(String node, String script) {
        return new AppProperties("target/x", "../keys", "http://localhost:5173", 100, node, script, "..", false, "");
    }

    @Test
    void missingBridgeOrNodeIsReportedAsUnavailableNotAsInvalidProof() {
        ZkpService noScript = new ZkpService(props("node", "../zkp/does-not-exist.js"));
        ApiException e1 = assertThrows(ApiException.class,
                () -> noScript.verify("age_check", new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode(), java.util.List.of()));
        assertEquals(503, e1.status());
        assertEquals("ZKP_UNAVAILABLE", e1.code());

        ZkpService noNode = new ZkpService(props("definitely-not-node-xyz", "../zkp/zk-bridge.js"));
        ApiException e2 = assertThrows(ApiException.class, () -> noNode.prove("age_check", Map.of()));
        assertEquals(503, e2.status());
    }

    @Test
    void malformedProofIsInvalidNotServerError() {
        ZkpService real = new ZkpService(props("node", "../zkp/zk-bridge.js"));
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        var proof = mapper.createObjectNode().put("A", "garbage");
        assertFalse(real.verify("age_check", proof, java.util.List.of("1", "2", "3", "4", "5")));
    }
}
