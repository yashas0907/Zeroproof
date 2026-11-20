package com.zeroproof.crypto;

import java.nio.file.Path;

/** Test-only bridge to the package-private key loader. */
public final class DocumentCryptoTestAccess {
    private DocumentCryptoTestAccess() { }

    public static byte[] load(String envKey, Path keyFile) {
        return DocumentCrypto.loadKey(envKey, keyFile);
    }
}
