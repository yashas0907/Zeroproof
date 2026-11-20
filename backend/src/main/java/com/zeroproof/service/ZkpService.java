package com.zeroproof.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.zeroproof.api.ApiException;
import com.zeroproof.config.AppProperties;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Orchestrates the existing Circom/snarkjs PLONK workflow. Java decides what to prove and verify;
 * the tiny Node bridge (zkp/zk-bridge.js) only executes snarkjs.
 */
@Service
public class ZkpService {
    /** Public-signal order of each circuit: outputs first, then public inputs in declaration order. */
    public static final Map<String, List<String>> SIGNALS = Map.of(
            "age_check", List.of("isEligible", "nullifierHash", "currentYear", "ageLimit", "externalNullifier"),
            "range_check", List.of("inRange", "nullifierHash", "currentYear", "minAge", "maxAge", "externalNullifier"));

    private final AppProperties props;
    private final ObjectMapper mapper = new ObjectMapper();

    public ZkpService(AppProperties props) {
        this.props = props;
    }

    public record ProofResult(JsonNode proof, List<String> publicSignals) { }

    public ProofResult prove(String circuit, Map<String, Object> inputs) {
        ObjectNode req = mapper.createObjectNode();
        req.put("cmd", "prove");
        req.put("circuit", circuit);
        req.set("inputs", mapper.valueToTree(inputs));
        JsonNode out = call(req, 120);
        if (!out.path("ok").asBoolean()) {
            throw new ApiException(502, "ZKP_FAILED", "Proof generation failed");
        }
        List<String> signals = mapper.convertValue(out.get("publicSignals"),
                mapper.getTypeFactory().constructCollectionType(List.class, String.class));
        return new ProofResult(out.get("proof"), signals);
    }

    /** @return true only if snarkjs accepts the proof against the circuit's verification key */
    public boolean verify(String circuit, JsonNode proof, List<String> publicSignals) {
        ObjectNode req = mapper.createObjectNode();
        req.put("cmd", "verify");
        req.put("circuit", circuit);
        req.set("proof", proof);
        req.set("publicSignals", mapper.valueToTree(publicSignals));
        JsonNode out;
        try {
            out = call(req, 60);
        } catch (ApiException e) {
            throw e;
        }
        if (!out.path("ok").asBoolean()) {
            // Malformed proofs make snarkjs throw; that is a rejection, not a server fault.
            return false;
        }
        return out.path("valid").asBoolean(false);
    }

    private JsonNode call(ObjectNode req, int timeoutSeconds) {
        req.put("keysDir", Path.of(props.keysDir()).toAbsolutePath().normalize().toString());
        Path script = Path.of(props.bridgeScript()).toAbsolutePath().normalize();
        Process p = null;
        try {
            p = new ProcessBuilder(props.nodeCommand(), script.toString())
                    .directory(script.getParent().toFile())
                    .redirectError(ProcessBuilder.Redirect.DISCARD)
                    .start();
            try (var in = p.getOutputStream()) {
                in.write(mapper.writeValueAsBytes(req));
            }
            InputStream stdout = p.getInputStream();
            byte[][] holder = new byte[1][];
            Thread reader = Thread.startVirtualThread(() -> {
                try {
                    holder[0] = stdout.readAllBytes();
                } catch (IOException ignored) {
                    holder[0] = new byte[0];
                }
            });
            if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                throw new ApiException(504, "ZKP_TIMEOUT", "ZKP operation timed out");
            }
            reader.join(5000);
            String text = new String(holder[0] == null ? new byte[0] : holder[0], StandardCharsets.UTF_8).trim();
            if (text.isEmpty()) {
                throw new ApiException(502, "ZKP_UNAVAILABLE", "ZKP bridge returned no output (is Node.js installed?)");
            }
            return mapper.readTree(text);
        } catch (IOException e) {
            throw new ApiException(502, "ZKP_UNAVAILABLE", "ZKP bridge could not be started (is Node.js installed?)");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApiException(502, "ZKP_FAILED", "ZKP operation interrupted");
        } finally {
            if (p != null && p.isAlive()) {
                p.destroyForcibly();
            }
        }
    }
}
