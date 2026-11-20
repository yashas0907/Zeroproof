package com.zeroproof.service;

import com.zeroproof.api.ApiException;
import com.zeroproof.entity.NullifierEntity;
import com.zeroproof.entity.Repositories.NullifierRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/** Replay prevention. The nullifier is the primary key, so check-and-store is atomic across threads. */
@Service
public class NullifierService {
    private final NullifierRepository repo;

    public NullifierService(NullifierRepository repo) {
        this.repo = repo;
    }

    /** @throws ApiException 409 NULLIFIER_REPLAYED if this nullifier was already consumed */
    public void register(String nullifierHash, String proofType, String credentialId) {
        if (nullifierHash == null || nullifierHash.isBlank() || nullifierHash.equals("0")) {
            throw ApiException.badRequest("VALIDATION_ERROR", "Proof must contain a non-zero nullifier");
        }
        try {
            repo.saveAndFlush(new NullifierEntity(nullifierHash, proofType, credentialId));
        } catch (DataIntegrityViolationException e) {
            throw replayed();
        }
    }

    public Optional<NullifierEntity> find(String nullifierHash) {
        return repo.findById(nullifierHash);
    }

    static ApiException replayed() {
        return new ApiException(409, "NULLIFIER_REPLAYED", "This nullifier has already been used in this context");
    }
}
