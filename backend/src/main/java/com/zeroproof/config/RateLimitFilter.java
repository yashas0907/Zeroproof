package com.zeroproof.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Fixed-window per-IP rate limiter plus request-id header (replaces the Express middleware). */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class RateLimitFilter extends OncePerRequestFilter {
    private static final long WINDOW_MS = 60_000;

    private record Window(long start, int count) { }

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final int max;
    private final ObjectMapper mapper = new ObjectMapper();

    public RateLimitFilter(AppProperties props) {
        this.max = props.rateLimit();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        res.setHeader("X-Request-ID", UUID.randomUUID().toString());
        if ("OPTIONS".equals(req.getMethod())) {
            chain.doFilter(req, res);
            return;
        }
        long now = System.currentTimeMillis();
        String ip = req.getRemoteAddr();
        Window w = windows.compute(ip, (k, old) ->
                (old == null || now - old.start() > WINDOW_MS) ? new Window(now, 1) : new Window(old.start(), old.count() + 1));
        if (windows.size() > 10_000) {
            windows.entrySet().removeIf(e -> now - e.getValue().start() > WINDOW_MS);
        }
        res.setHeader("X-RateLimit-Limit", String.valueOf(max));
        res.setHeader("X-RateLimit-Remaining", String.valueOf(Math.max(0, max - w.count())));
        if (w.count() > max) {
            long retry = Math.max(1, (w.start() + WINDOW_MS - now + 999) / 1000);
            res.setHeader("Retry-After", String.valueOf(retry));
            res.setStatus(429);
            res.setContentType("application/json");
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("status", "error");
            body.put("data", null);
            body.put("meta", Map.of("timestamp", Instant.now().toString()));
            body.put("error", Map.of("code", "RATE_LIMITED", "message", "Too many requests, please try again later"));
            mapper.writeValue(res.getOutputStream(), body);
            return;
        }
        chain.doFilter(req, res);
    }
}
