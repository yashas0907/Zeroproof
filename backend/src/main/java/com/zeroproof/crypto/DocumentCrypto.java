package com.zeroproof.crypto;

import com.zeroproof.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * AES-256-GCM document encryption. Blob layout is identical to the legacy Node backend:
 * iv(16) | authTag(16) | ciphertext.
 *
 * Key source, in order: AEGISID_DOC_KEY (64 hex chars) or a persistent local key file generated once
 * (data/keys/doc.key). The key is never logged or exposed through any API.
 */
@Component
public class DocumentCrypto {
    private static final Logger log = LoggerFactory.getLogger(DocumentCrypto.class);
    private static final int IV_LEN = 16;
    private static final int TAG_LEN = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKeySpec key;

    @org.springframework.beans.factory.annotation.Autowired
    public DocumentCrypto(AppProperties props) {
        this(loadKey(props.docKey(), Path.of(props.dataDir(), "keys", "doc.key")));
    }

    public DocumentCrypto(byte[] rawKey) {
        if (rawKey.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be 32 bytes");
        }
        this.key = new SecretKeySpec(rawKey, "AES");
    }

    static byte[] loadKey(String envKey, Path keyFile) {
        if (envKey != null && !envKey.isBlank()) {
            return parseHexKey(envKey.trim(), "AEGISID_DOC_KEY");
        }
        try {
            if (Files.exists(keyFile)) {
                return parseHexKey(Files.readString(keyFile).trim(), keyFile.toString());
            }
            byte[] fresh = new byte[32];
            RANDOM.nextBytes(fresh);
            Files.createDirectories(keyFile.toAbsolutePath().getParent());
            Files.writeString(keyFile, HexFormat.of().formatHex(fresh));
            try {
                keyFile.toFile().setReadable(false, false);
                keyFile.toFile().setReadable(true, true);
                keyFile.toFile().setWritable(false, false);
                keyFile.toFile().setWritable(true, true);
            } catch (SecurityException ignored) {
                // best effort owner-only permissions
            }
            log.info("Generated a new persistent document key at {}", keyFile.toAbsolutePath());
            return fresh;
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read or create the document encryption key file", e);
        }
    }

    private static byte[] parseHexKey(String hex, String source) {
        if (!hex.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalStateException("Document key from " + source + " must be exactly 64 hex characters");
        }
        return HexFormat.of().parseHex(hex);
    }

    public byte[] encrypt(byte[] plain) {
        try {
            byte[] iv = new byte[IV_LEN];
            RANDOM.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LEN * 8, iv));
            byte[] out = c.doFinal(plain); // ciphertext | tag
            int ctLen = out.length - TAG_LEN;
            byte[] blob = new byte[IV_LEN + TAG_LEN + ctLen];
            System.arraycopy(iv, 0, blob, 0, IV_LEN);
            System.arraycopy(out, ctLen, blob, IV_LEN, TAG_LEN);
            System.arraycopy(out, 0, blob, IV_LEN + TAG_LEN, ctLen);
            return blob;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    /** @throws GeneralSecurityException if the blob is malformed, tampered with, or the key is wrong */
    public byte[] decrypt(byte[] blob) throws GeneralSecurityException {
        if (blob.length < IV_LEN + TAG_LEN) {
            throw new GeneralSecurityException("Encrypted blob too short");
        }
        byte[] iv = Arrays.copyOfRange(blob, 0, IV_LEN);
        byte[] tag = Arrays.copyOfRange(blob, IV_LEN, IV_LEN + TAG_LEN);
        byte[] ct = Arrays.copyOfRange(blob, IV_LEN + TAG_LEN, blob.length);
        byte[] joined = new byte[ct.length + TAG_LEN];
        System.arraycopy(ct, 0, joined, 0, ct.length);
        System.arraycopy(tag, 0, joined, ct.length, TAG_LEN);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LEN * 8, iv));
        return c.doFinal(joined);
    }
}
