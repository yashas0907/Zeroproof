package com.zeroproof.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "share_links", indexes = @Index(columnList = "credentialId"))
public class ShareLinkEntity {
    @Id
    private String token;
    private String credentialId;
    private String organizationName;
    private Instant createdAt;
    private Instant expiresAt;
    private String status = "active";
    private int verificationCount;
    private Instant lastVerifiedAt;
    private Instant revokedAt;

    public String getToken() { return token; }
    public void setToken(String v) { this.token = v; }
    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String v) { this.credentialId = v; }
    public String getOrganizationName() { return organizationName; }
    public void setOrganizationName(String v) { this.organizationName = v; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant v) { this.createdAt = v; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant v) { this.expiresAt = v; }
    public String getStatus() { return status; }
    public void setStatus(String v) { this.status = v; }
    public int getVerificationCount() { return verificationCount; }
    public void setVerificationCount(int v) { this.verificationCount = v; }
    public Instant getLastVerifiedAt() { return lastVerifiedAt; }
    public void setLastVerifiedAt(Instant v) { this.lastVerifiedAt = v; }
    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant v) { this.revokedAt = v; }
}
