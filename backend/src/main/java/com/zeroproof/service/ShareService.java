package com.zeroproof.service;

import com.zeroproof.api.ApiException;
import com.zeroproof.entity.CredentialEntity;
import com.zeroproof.entity.Repositories.ShareLinkRepository;
import com.zeroproof.entity.ShareLinkEntity;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;

@Service
public class ShareService {
    private static final long MAX_HOURS = 24L * 365;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final ShareLinkRepository shares;
    private final CredentialService credentials;

    public ShareService(ShareLinkRepository shares, CredentialService credentials) {
        this.shares = shares;
        this.credentials = credentials;
    }

    public ShareLinkEntity create(String credentialId, Long expiresInHours, String organizationName) {
        CredentialEntity c = credentials.get(credentialId);
        if (!"active".equals(c.getStatus()) || c.getExpiresAt().isBefore(Instant.now())) {
            throw new ApiException(409, "CREDENTIAL_INACTIVE", "Credential is revoked or expired");
        }
        long hours = expiresInHours == null ? 72 : expiresInHours;
        if (hours <= 0 || hours > MAX_HOURS) {
            throw ApiException.badRequest("VALIDATION_ERROR", "expiresInHours must be between 1 and " + MAX_HOURS);
        }
        byte[] raw = new byte[24];
        RANDOM.nextBytes(raw);
        Instant now = Instant.now();
        ShareLinkEntity s = new ShareLinkEntity();
        s.setToken(Base64.getUrlEncoder().withoutPadding().encodeToString(raw));
        s.setCredentialId(credentialId);
        s.setOrganizationName(organizationName == null ? "" : organizationName);
        s.setCreatedAt(now);
        s.setExpiresAt(now.plus(hours, ChronoUnit.HOURS));
        return shares.save(s);
    }

    public List<ShareLinkEntity> listActive(String credentialId) {
        return shares.findByCredentialIdAndStatus(credentialId, "active");
    }

    /** Revokes a link, but only through the credential that owns it. */
    public void revoke(String credentialId, String token) {
        ShareLinkEntity s = shares.findById(token == null ? "" : token)
                .filter(x -> x.getCredentialId().equals(credentialId))
                .orElseThrow(() -> ApiException.notFound("SHARE_NOT_FOUND", "Share link not found"));
        s.setStatus("revoked");
        s.setRevokedAt(Instant.now());
        shares.save(s);
    }

    /** Looks up a usable link; throws 404 INVALID_SHARE_LINK for unknown, revoked or expired tokens. */
    public ShareLinkEntity requireUsable(String token) {
        ShareLinkEntity s = shares.findById(token)
                .orElseThrow(() -> ApiException.notFound("INVALID_SHARE_LINK", "Share link not found"));
        if ("revoked".equals(s.getStatus())) {
            throw ApiException.notFound("INVALID_SHARE_LINK", "Share link has been revoked");
        }
        if (s.getExpiresAt().isBefore(Instant.now())) {
            throw ApiException.notFound("INVALID_SHARE_LINK", "Share link has expired");
        }
        return s;
    }

    public void recordVerification(ShareLinkEntity s) {
        s.setVerificationCount(s.getVerificationCount() + 1);
        s.setLastVerifiedAt(Instant.now());
        shares.save(s);
    }
}
