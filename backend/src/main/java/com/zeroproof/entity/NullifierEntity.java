package com.zeroproof.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import org.springframework.data.domain.Persistable;

import java.time.Instant;

/**
 * A consumed nullifier. The primary key makes check-and-store atomic; implementing Persistable
 * forces an INSERT (not a merge), so a duplicate raises a constraint violation instead of overwriting.
 */
@Entity
@Table(name = "nullifiers")
public class NullifierEntity implements Persistable<String> {
    @Id
    private String nullifierHash;
    private String proofType;
    /** Set when the nullifier was registered at credential issuance. */
    private String credentialId;
    private Instant usedAt;
    @Transient
    private boolean isNew = true;

    public NullifierEntity() { }

    public NullifierEntity(String nullifierHash, String proofType, String credentialId) {
        this.nullifierHash = nullifierHash;
        this.proofType = proofType;
        this.credentialId = credentialId;
        this.usedAt = Instant.now();
    }

    @Override
    public String getId() { return nullifierHash; }

    @Override
    public boolean isNew() { return isNew; }

    @PostLoad
    @PostPersist
    void markNotNew() { this.isNew = false; }

    public String getNullifierHash() { return nullifierHash; }
    public String getProofType() { return proofType; }
    public String getCredentialId() { return credentialId; }
    public Instant getUsedAt() { return usedAt; }
}
