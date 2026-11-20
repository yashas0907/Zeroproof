package com.zeroproof.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "credentials")
public class CredentialEntity {
    @Id
    private String id;
    private String documentId;
    private String documentHash;
    private String credentialType;
    private String fullName;
    private String dateOfBirth;
    private String documentType;
    private String nameHash;
    @Lob
    @Column(columnDefinition = "CLOB")
    private String proofJson;
    @Lob
    @Column(columnDefinition = "CLOB")
    private String publicSignalsJson;
    private boolean proofVerified;
    private String circuit;
    private String nullifierHash;
    private String externalNullifier;
    private int issuedYear;
    private String attributeHash;
    private Instant issuedAt;
    private Instant expiresAt;
    private Instant revokedAt;
    private String status = "active";
    private boolean eligible;
    private int age;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getDocumentId() { return documentId; }
    public void setDocumentId(String v) { this.documentId = v; }
    public String getDocumentHash() { return documentHash; }
    public void setDocumentHash(String v) { this.documentHash = v; }
    public String getCredentialType() { return credentialType; }
    public void setCredentialType(String v) { this.credentialType = v; }
    public String getFullName() { return fullName; }
    public void setFullName(String v) { this.fullName = v; }
    public String getDateOfBirth() { return dateOfBirth; }
    public void setDateOfBirth(String v) { this.dateOfBirth = v; }
    public String getDocumentType() { return documentType; }
    public void setDocumentType(String v) { this.documentType = v; }
    public String getNameHash() { return nameHash; }
    public void setNameHash(String v) { this.nameHash = v; }
    public String getProofJson() { return proofJson; }
    public void setProofJson(String v) { this.proofJson = v; }
    public String getPublicSignalsJson() { return publicSignalsJson; }
    public void setPublicSignalsJson(String v) { this.publicSignalsJson = v; }
    public boolean isProofVerified() { return proofVerified; }
    public void setProofVerified(boolean v) { this.proofVerified = v; }
    public String getCircuit() { return circuit; }
    public void setCircuit(String v) { this.circuit = v; }
    public String getNullifierHash() { return nullifierHash; }
    public void setNullifierHash(String v) { this.nullifierHash = v; }
    public String getExternalNullifier() { return externalNullifier; }
    public void setExternalNullifier(String v) { this.externalNullifier = v; }
    public int getIssuedYear() { return issuedYear; }
    public void setIssuedYear(int v) { this.issuedYear = v; }
    public String getAttributeHash() { return attributeHash; }
    public void setAttributeHash(String v) { this.attributeHash = v; }
    public Instant getIssuedAt() { return issuedAt; }
    public void setIssuedAt(Instant v) { this.issuedAt = v; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant v) { this.expiresAt = v; }
    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant v) { this.revokedAt = v; }
    public String getStatus() { return status; }
    public void setStatus(String v) { this.status = v; }
    public boolean isEligible() { return eligible; }
    public void setEligible(boolean v) { this.eligible = v; }
    public int getAge() { return age; }
    public void setAge(int v) { this.age = v; }
}
