package com.zeroproof.service;

import com.zeroproof.api.ApiException;
import com.zeroproof.config.AppProperties;
import com.zeroproof.crypto.DocumentCrypto;
import com.zeroproof.crypto.Hashing;
import com.zeroproof.entity.DocumentEntity;
import com.zeroproof.entity.Repositories.DocumentRepository;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class DocumentService {
    private final DocumentRepository docs;
    private final DocumentCrypto crypto;
    private final TextExtractor extractor;
    private final Path vaultDir;

    public DocumentService(DocumentRepository docs, DocumentCrypto crypto, TextExtractor extractor, AppProperties props) {
        this.docs = docs;
        this.crypto = crypto;
        this.extractor = extractor;
        this.vaultDir = Path.of(props.dataDir(), "java", "vault");
    }

    public record UploadResult(DocumentEntity document, boolean duplicate, DocumentAnalyzer.Result extracted) { }

    public UploadResult upload(byte[] bytes, String originalName, String mimeType,
                               String formName, String formDob, String formType) {
        if (bytes.length == 0) {
            throw ApiException.badRequest("NO_FILE", "No document file provided.");
        }
        if (mimeType == null || !(mimeType.startsWith("image/") || mimeType.equals("application/pdf"))) {
            throw ApiException.badRequest("INVALID_FILE_TYPE", "Only images or PDFs are supported.");
        }

        DocumentAnalyzer.Result extracted;
        try {
            extracted = DocumentAnalyzer.analyze(extractor.extract(bytes, mimeType));
        } catch (RuntimeException e) {
            extracted = new DocumentAnalyzer.Result("", "", "other", "ERROR", "Analysis failed. Please enter details manually.");
        }

        String name = firstNonBlank(extracted.name(), formName);
        String dob = firstNonBlank(extracted.dateOfBirth(), formDob);
        String type = extracted.documentType() != null && !"other".equals(extracted.documentType())
                ? extracted.documentType() : firstNonBlank(formType, "other");

        String hash = Hashing.sha256Hex(bytes);
        Optional<DocumentEntity> existing = docs.findFirstByDocumentHashAndStatus(hash, "active");
        if (existing.isPresent()) {
            return new UploadResult(existing.get(), true, withAttributes(extracted, name, dob, type));
        }

        String id = UUID.randomUUID().toString();
        Path file = vaultDir.resolve(id + ".enc");
        try {
            Files.createDirectories(vaultDir);
            Files.write(file, crypto.encrypt(bytes));
        } catch (IOException e) {
            throw new ApiException(500, "STORAGE_ERROR", "Could not store the document");
        }

        DocumentEntity d = new DocumentEntity();
        d.setId(id);
        d.setOriginalName(originalName == null ? "document" : originalName);
        d.setMimeType(mimeType);
        d.setSizeBytes(bytes.length);
        d.setDocumentHash(hash);
        d.setFullName(name);
        d.setDateOfBirth(dob);
        d.setDocumentType(type);
        d.setExtractStatus(extracted.status());
        d.setReason(extracted.reason());
        d.setVerified(!name.isEmpty() && !dob.isEmpty());
        d.setVaultPath(file.toString());
        d.setCreatedAt(Instant.now());
        docs.save(d);
        return new UploadResult(d, false, withAttributes(extracted, name, dob, type));
    }

    private static DocumentAnalyzer.Result withAttributes(DocumentAnalyzer.Result r, String name, String dob, String type) {
        return new DocumentAnalyzer.Result(name, dob, type, r.status(), r.reason());
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) return a;
        return b == null ? "" : b;
    }

    public List<DocumentEntity> list() {
        return docs.findByStatusOrderByCreatedAtDesc("active");
    }

    public DocumentEntity get(String id) {
        return docs.findByIdAndStatus(id, "active")
                .orElseThrow(() -> ApiException.notFound("DOCUMENT_NOT_FOUND", "Document not found"));
    }

    /** Decrypts and returns the original document bytes (local owner access only; never via share links). */
    public byte[] readDecrypted(DocumentEntity d) {
        Path file = d.getVaultPath() == null ? null : Path.of(d.getVaultPath());
        if (file == null || !Files.isRegularFile(file)) {
            throw new ApiException(410, "DOCUMENT_FILE_MISSING", "The encrypted file for this document is not available");
        }
        byte[] plain;
        try {
            plain = crypto.decrypt(Files.readAllBytes(file));
        } catch (java.security.GeneralSecurityException e) {
            throw new ApiException(409, "DOCUMENT_UNREADABLE",
                    "The document cannot be decrypted with the configured key (it may have been encrypted with a different key)");
        } catch (IOException e) {
            throw new ApiException(500, "STORAGE_ERROR", "Could not read the document");
        }
        if (!Hashing.sha256Hex(plain).equals(d.getDocumentHash())) {
            throw new ApiException(409, "DOCUMENT_INTEGRITY_ERROR", "Decrypted document does not match its stored hash");
        }
        return plain;
    }

    public void delete(String id) {
        DocumentEntity d = get(id);
        d.setStatus("deleted");
        docs.save(d);
        try {
            // Only ciphertext written by this backend is removed; imported legacy vault files are never touched.
            if (d.getVaultPath() != null) {
                Path file = Path.of(d.getVaultPath()).toAbsolutePath().normalize();
                if (file.startsWith(vaultDir.toAbsolutePath().normalize())) {
                    Files.deleteIfExists(file);
                }
            }
        } catch (IOException ignored) {
            // metadata is already marked deleted; the orphaned ciphertext is harmless
        }
    }
}
