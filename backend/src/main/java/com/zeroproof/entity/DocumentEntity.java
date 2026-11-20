package com.zeroproof.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "documents", indexes = @Index(columnList = "documentHash"))
public class DocumentEntity {
    @Id
    private String id;
    private String originalName;
    private String mimeType;
    private long sizeBytes;
    @Column(nullable = false)
    private String documentHash;
    private String fullName;
    private String dateOfBirth;
    private String documentType;
    private String extractStatus;
    @Column(length = 1000)
    private String reason;
    private boolean verified;
    private String encryptionAlgorithm = "AES-256-GCM";
    private String vaultPath;
    private String status = "active";
    private Instant createdAt;
    /** Non-null for records imported from the legacy Node data files. */
    @Column(length = 500)
    private String importNote;

    public String getImportNote() { return importNote; }
    public void setImportNote(String v) { this.importNote = v; }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getOriginalName() { return originalName; }
    public void setOriginalName(String v) { this.originalName = v; }
    public String getMimeType() { return mimeType; }
    public void setMimeType(String v) { this.mimeType = v; }
    public long getSizeBytes() { return sizeBytes; }
    public void setSizeBytes(long v) { this.sizeBytes = v; }
    public String getDocumentHash() { return documentHash; }
    public void setDocumentHash(String v) { this.documentHash = v; }
    public String getFullName() { return fullName; }
    public void setFullName(String v) { this.fullName = v; }
    public String getDateOfBirth() { return dateOfBirth; }
    public void setDateOfBirth(String v) { this.dateOfBirth = v; }
    public String getDocumentType() { return documentType; }
    public void setDocumentType(String v) { this.documentType = v; }
    public String getExtractStatus() { return extractStatus; }
    public void setExtractStatus(String v) { this.extractStatus = v; }
    public String getReason() { return reason; }
    public void setReason(String v) { this.reason = v; }
    public boolean isVerified() { return verified; }
    public void setVerified(boolean v) { this.verified = v; }
    public String getEncryptionAlgorithm() { return encryptionAlgorithm; }
    public void setEncryptionAlgorithm(String v) { this.encryptionAlgorithm = v; }
    public String getVaultPath() { return vaultPath; }
    public void setVaultPath(String v) { this.vaultPath = v; }
    public String getStatus() { return status; }
    public void setStatus(String v) { this.status = v; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant v) { this.createdAt = v; }
}
