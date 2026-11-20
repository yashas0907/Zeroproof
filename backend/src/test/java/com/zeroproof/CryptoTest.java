package com.zeroproof;

import com.zeroproof.crypto.DocumentCrypto;
import com.zeroproof.crypto.Hashing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class CryptoTest {
    private static byte[] randomKey() {
        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);
        return k;
    }

    @Test
    void sha256MatchesKnownVector() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Hashing.sha256Hex("abc"));
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Hashing.sha256Hex(new byte[0]));
    }

    @Test
    void derivationsMatchLegacyNodeValues() {
        // Golden values produced by the legacy credentialIssuer.js algorithm.
        assertEquals("565704015915253723906549121166220642081325899971", Hashing.deriveSecret("abc-hash", "cred-1"));
        assertEquals("713184883", Hashing.deriveExternalNullifier("cred-1"));
    }

    @Test
    void aesGcmRoundTripAndRandomIv() throws Exception {
        DocumentCrypto c = new DocumentCrypto(randomKey());
        byte[] plain = "secret identity document".getBytes(StandardCharsets.UTF_8);
        byte[] a = c.encrypt(plain);
        byte[] b = c.encrypt(plain);
        assertEquals(plain.length + 32, a.length, "iv(16)+tag(16)+ciphertext layout");
        assertFalse(java.util.Arrays.equals(a, b), "fresh IV per encryption");
        assertArrayEquals(plain, c.decrypt(a));
    }

    @Test
    void tamperedCiphertextOrTagIsRejected() {
        DocumentCrypto c = new DocumentCrypto(randomKey());
        byte[] blob = c.encrypt("hello world".getBytes(StandardCharsets.UTF_8));
        for (int pos : new int[]{0, 20, blob.length - 1}) { // iv, tag, ciphertext
            byte[] bad = blob.clone();
            bad[pos] ^= 1;
            assertThrows(GeneralSecurityException.class, () -> c.decrypt(bad), "tamper at " + pos);
        }
        assertThrows(GeneralSecurityException.class, () -> c.decrypt(new byte[10]));
    }

    @Test
    void wrongKeyCannotDecrypt() {
        byte[] blob = new DocumentCrypto(randomKey()).encrypt("data".getBytes(StandardCharsets.UTF_8));
        assertThrows(GeneralSecurityException.class, () -> new DocumentCrypto(randomKey()).decrypt(blob));
    }

    @Test
    void keyFileIsGeneratedOnceAndSurvivesRestart(@TempDir Path dir) throws Exception {
        Path keyFile = dir.resolve("keys").resolve("doc.key");
        DocumentCrypto first = new DocumentCrypto(com.zeroproof.crypto.DocumentCryptoTestAccess.load("", keyFile));
        assertTrue(Files.exists(keyFile));
        byte[] blob = first.encrypt("persist me".getBytes(StandardCharsets.UTF_8));
        // "restart": a brand new instance loads the same key file
        DocumentCrypto second = new DocumentCrypto(com.zeroproof.crypto.DocumentCryptoTestAccess.load("", keyFile));
        assertArrayEquals("persist me".getBytes(StandardCharsets.UTF_8), second.decrypt(blob));
    }

    @Test
    void envKeyOverridesFileAndMalformedKeysAreRefused(@TempDir Path dir) throws Exception {
        String hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        Path keyFile = dir.resolve("doc.key");
        DocumentCrypto fromEnv = new DocumentCrypto(com.zeroproof.crypto.DocumentCryptoTestAccess.load(hex, keyFile));
        assertFalse(Files.exists(keyFile), "env key must not create a key file");
        byte[] blob = fromEnv.encrypt(new byte[]{1, 2, 3});
        assertArrayEquals(new byte[]{1, 2, 3}, new DocumentCrypto(com.zeroproof.crypto.DocumentCryptoTestAccess.load(hex, keyFile)).decrypt(blob));

        assertThrows(IllegalStateException.class, () -> com.zeroproof.crypto.DocumentCryptoTestAccess.load("tooshort", keyFile));
        assertThrows(IllegalStateException.class, () -> com.zeroproof.crypto.DocumentCryptoTestAccess.load("zz".repeat(32), keyFile));
    }
}
