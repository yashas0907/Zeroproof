package com.zeroproof.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.zeroproof.api.ApiException;
import com.zeroproof.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Orchestrates the existing Circom/snarkjs PLONK workflow. Java decides what to prove and verify;
 * the tiny Node bridge (zkp/zk-bridge.js) only executes snarkjs. Each call is a short-lived process
 * with a timeout; concurrent calls are bounded to protect the host.
 */
@Service
public class ZkpService {
    private static final Logger log = LoggerFactory.getLogger(ZkpService.class);
    private static final int MAX_OUTPUT_BYTES = 1_000_000;

    /** Public-signal order of each circuit: outputs first, then public inputs in declaration order. */
    public static final Map<String, List<String>> SIGNALS = Map.of(
            "age_check", List.of("isEligible", "nullifierHash", "currentYear", "ageLimit", "externalNullifier"),
            "range_check", List.of("inRange", "nullifierHash", "currentYear", "minAge", "maxAge", "externalNullifier"));

    private final AppProperties props;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Semaphore slots = new Semaphore(Math.max(2, Runtime.getRuntime().availableProcessors()));

    public ZkpService(AppProperties props) {
        this.props = props;
    }

    public record ProofResult(JsonNode proof, List<String> publicSignals) { }

    public ProofResult prove(String circuit, Map<String, Object> inputs) {
        requireCircuit(circuit);
        ObjectNode req = mapper.createObjectNode();
        req.put("cmd", "prove");
        req.put("circuit", circuit);
        req.set("inputs", mapper.valueToTree(inputs));
        JsonNode out = call(req, 120);
        if (!out.path("ok").asBoolean()) {
            if ("input".equals(out.path("kind").asText())) {
                throw ApiException.badRequest("INVALID_CIRCUIT_INPUT", "The circuit rejected the inputs");
            }
            log.error("ZKP bridge prove failed: {}", out.path("error").asText());
            throw new ApiException(502, "ZKP_FAILED", "Proof generation failed");
        }
        JsonNode sig = out.get("publicSignals");
        if (out.get("proof") == null || sig == null || !sig.isArray()) {
            throw new ApiException(502, "ZKP_FAILED", "ZKP bridge returned an incomplete proof");
        }
        List<String> signals = mapper.convertValue(sig, mapper.getTypeFactory().constructCollectionType(List.class, String.class));
        return new ProofResult(out.get("proof"), signals);
    }

    /**
     * @return true only if snarkjs accepts the proof against the circuit's verification key;
     *         false for invalid or malformed proofs.
     * @throws ApiException if the proving toolchain itself is unavailable (never reported as "invalid")
     */
    public boolean verify(String circuit, JsonNode proof, List<String> publicSignals) {
        requireCircuit(circuit);
        ObjectNode req = mapper.createObjectNode();
        req.put("cmd", "verify");
        req.put("circuit", circuit);
        req.set("proof", proof);
        req.set("publicSignals", mapper.valueToTree(publicSignals));
        JsonNode out = call(req, 60);
        if (out.path("ok").asBoolean()) {
            return out.path("valid").asBoolean(false);
        }
        if ("input".equals(out.path("kind").asText())) {
            return false;
        }
        log.error("ZKP bridge verify failed: {}", out.path("error").asText());
        throw new ApiException(503, "ZKP_UNAVAILABLE", "Proof verification is temporarily unavailable");
    }

    private static void requireCircuit(String circuit) {
        if (!SIGNALS.containsKey(circuit)) {
            throw ApiException.badRequest("VALIDATION_ERROR", "Unsupported proof type '" + circuit + "'");
        }
    }

    private JsonNode call(ObjectNode req, int timeoutSeconds) {
        Path script = Path.of(props.bridgeScript()).toAbsolutePath().normalize();
        if (!Files.isRegularFile(script)) {
            log.error("ZKP bridge script not found at {}", script);
            throw new ApiException(503, "ZKP_UNAVAILABLE", "ZKP bridge is not installed");
        }
        req.put("keysDir", Path.of(props.keysDir()).toAbsolutePath().normalize().toString());
        boolean acquired = false;
        Process p = null;
        try {
            acquired = slots.tryAcquire(timeoutSeconds, TimeUnit.SECONDS);
            if (!acquired) {
                throw new ApiException(503, "ZKP_BUSY", "Too many concurrent proof operations, try again shortly");
            }
            p = new ProcessBuilder(props.nodeCommand(), script.toString())
                    .directory(script.getParent().toFile())
                    .redirectError(ProcessBuilder.Redirect.DISCARD)
                    .start();
            final Process proc = p;
            CompletableFuture<byte[]> stdout = CompletableFuture.supplyAsync(() -> {
                try {
                    return proc.getInputStream().readNBytes(MAX_OUTPUT_BYTES);
                } catch (IOException e) {
                    return new byte[0];
                }
            });
            try (var in = p.getOutputStream()) {
                in.write(mapper.writeValueAsBytes(req));
            }
            if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                throw new ApiException(504, "ZKP_TIMEOUT", "ZKP operation timed out");
            }
            String text = new String(stdout.get(5, TimeUnit.SECONDS), StandardCharsets.UTF_8).trim();
            if (text.isEmpty()) {
                throw new ApiException(503, "ZKP_UNAVAILABLE", "ZKP bridge returned no output (is Node.js installed?)");
            }
            JsonNode out = mapper.readTree(text);
            if (!out.isObject() || !out.has("ok")) {
                throw new ApiException(502, "ZKP_FAILED", "ZKP bridge returned an unexpected response");
            }
            return out;
        } catch (ApiException e) {
            throw e;
        } catch (IOException e) {
            log.error("ZKP bridge could not run: {}", e.toString());
            throw new ApiException(503, "ZKP_UNAVAILABLE", "ZKP bridge could not be started (is Node.js installed?)");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApiException(503, "ZKP_UNAVAILABLE", "ZKP operation interrupted");
        } catch (Exception e) {
            log.error("ZKP bridge error: {}", e.toString());
            throw new ApiException(502, "ZKP_FAILED", "ZKP operation failed");
        } finally {
            if (p != null && p.isAlive()) {
                p.destroyForcibly();
            }
            if (acquired) {
                slots.release();
            }
        }
    }
}
