package com.zeroproof.entity;

import java.util.List;
import java.util.Optional;

/** Spring Data repositories, grouped in one file to keep the persistence layer compact. */
public final class Repositories {
    private Repositories() { }

    public interface DocumentRepository extends org.springframework.data.jpa.repository.JpaRepository<DocumentEntity, String> {
        Optional<DocumentEntity> findFirstByDocumentHashAndStatus(String hash, String status);

        Optional<DocumentEntity> findByIdAndStatus(String id, String status);

        List<DocumentEntity> findByStatusOrderByCreatedAtDesc(String status);
    }

    public interface CredentialRepository extends org.springframework.data.jpa.repository.JpaRepository<CredentialEntity, String> {
        List<CredentialEntity> findByStatusNotOrderByIssuedAtDesc(String status);

        List<CredentialEntity> findByDocumentIdAndStatusNotOrderByIssuedAtDesc(String documentId, String status);
    }

    public interface ShareLinkRepository extends org.springframework.data.jpa.repository.JpaRepository<ShareLinkEntity, String> {
        List<ShareLinkEntity> findByCredentialIdAndStatus(String credentialId, String status);
    }

    public interface NullifierRepository extends org.springframework.data.jpa.repository.JpaRepository<NullifierEntity, String> {
    }
}
