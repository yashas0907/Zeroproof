package com.zeroproof.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Application settings (zeroproof.* in application.properties). */
@ConfigurationProperties(prefix = "zeroproof")
public record AppProperties(
        String dataDir,
        String keysDir,
        String corsOrigin,
        int rateLimit,
        String nodeCommand,
        String bridgeScript,
        String tessdataDir,
        boolean importLegacy,
        String docKey) {
}
