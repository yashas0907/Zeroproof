package com.zeroproof.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** SHA-256 helpers and the credential-bound derivations that feed the Circom circuit. */
public final class Hashing {
    private Hashing() { }

    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha256Hex(String text) {
        return sha256Hex(text.getBytes(StandardCharsets.UTF_8));
    }

    /** Document-bound circuit secret: first 40 hex chars of SHA-256(documentHash + credentialId), as a decimal. */
    public static String deriveSecret(String documentHash, String credentialId) {
        return new BigInteger(sha256Hex(documentHash + credentialId).substring(0, 40), 16).toString();
    }

    /** Per-credential external nullifier: first 8 hex chars of SHA-256("aegisid-credential-" + id), as a decimal. */
    public static String deriveExternalNullifier(String credentialId) {
        return new BigInteger(sha256Hex("aegisid-credential-" + credentialId).substring(0, 8), 16).toString();
    }
}
