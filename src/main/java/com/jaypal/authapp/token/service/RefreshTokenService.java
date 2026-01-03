package com.jaypal.authapp.token.service;

import com.jaypal.authapp.exception.refresh.RefreshTokenExpiredException;
import com.jaypal.authapp.exception.refresh.RefreshTokenNotFoundException;
import com.jaypal.authapp.exception.refresh.RefreshTokenRevokedException;
import com.jaypal.authapp.exception.refresh.RefreshTokenUserMismatchException;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.repository.RefreshTokenRepository;
import com.jaypal.authapp.user.model.User;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    // -------------------------------------------------
    // ISSUE
    // -------------------------------------------------

    @Transactional
    public RefreshToken issue(User user, long ttlSeconds) {

        refreshTokenRepository.revokeAllActiveByUserId(user.getId());

        RefreshToken token = RefreshToken.builder()
                .jti(UUID.randomUUID().toString())
                .user(user)
                .expiresAt(Instant.now().plusSeconds(ttlSeconds))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(token);
    }

    // -------------------------------------------------
    // VALIDATE (FIXED)
    // -------------------------------------------------

    @Transactional
    public RefreshToken validate(String jti, UUID userId) {

        RefreshToken token =
                refreshTokenRepository.findByJtiWithUserAndRoles(jti)
                        .orElseThrow(RefreshTokenNotFoundException::new);

        if (token.isRevoked()) {
            throw new RefreshTokenRevokedException();
        }

        if (token.getExpiresAt().isBefore(Instant.now())) {
            throw new RefreshTokenExpiredException();
        }

        if (!token.getUser().getId().equals(userId)) {
            throw new RefreshTokenUserMismatchException();
        }

        return token;
    }

    // -------------------------------------------------
    // ROTATE
    // -------------------------------------------------

    @Transactional
    public RefreshToken rotate(RefreshToken current, long ttlSeconds) {

        current.setRevoked(true);

        String newJti = UUID.randomUUID().toString();
        current.setReplacedByToken(newJti);
        refreshTokenRepository.save(current);

        RefreshToken next = RefreshToken.builder()
                .jti(newJti)
                .user(current.getUser())
                .expiresAt(Instant.now().plusSeconds(ttlSeconds))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(next);
    }

    // -------------------------------------------------
    // REVOKE
    // -------------------------------------------------

    @Transactional
    public void revokeIfExists(String jti) {
        refreshTokenRepository.findByJti(jti)
                .ifPresent(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                });
    }
}
