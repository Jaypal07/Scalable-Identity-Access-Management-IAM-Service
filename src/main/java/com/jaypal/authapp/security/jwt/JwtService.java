package com.jaypal.authapp.security.jwt;

import com.jaypal.authapp.user.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Getter
public class JwtService {

    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_TYPE = "typ";

    private final SecretKey secretKey;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds,
            @Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
            @Value("${security.jwt.issuer}") String issuer
    ) {
        validateSecret(secret);
        this.secretKey = JwtUtils.createKey(secret);
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }

    // -------------------------------------------------
    // TOKEN GENERATION
    // -------------------------------------------------

    public String generateAccessToken(User user) {

        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_TYPE, TokenType.ACCESS.name().toLowerCase());
        claims.put(CLAIM_ROLES, extractRoles(user));

        if (user.getEmail() != null) {
            claims.put(CLAIM_EMAIL, user.getEmail());
        }

        return JwtUtils.buildToken(
                secretKey,
                issuer,
                user.getId(),
                claims,
                accessTtlSeconds
        );
    }

    public String generateRefreshToken(User user, String jti) {

        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_TYPE, TokenType.REFRESH.name().toLowerCase());

        return JwtUtils.buildRefreshToken(
                secretKey,
                issuer,
                user.getId(),
                claims,
                refreshTtlSeconds,
                jti
        );
    }

    // -------------------------------------------------
    // PARSE & VALIDATE
    // -------------------------------------------------

    public Jws<Claims> parse(String token) {
        return JwtUtils.parse(secretKey, issuer, token);
    }

    public boolean isAccessToken(Jws<Claims> parsed) {
        return TokenType.from(parsed.getBody().get(CLAIM_TYPE, String.class))
                == TokenType.ACCESS;
    }

    // -------------------------------------------------
    // CLAIM EXTRACTION (SAFE)
    // -------------------------------------------------

    public UUID extractUserId(Claims claims) {
        return UUID.fromString(claims.getSubject());
    }

    public String extractEmail(Claims claims) {
        return claims.get(CLAIM_EMAIL, String.class);
    }

    public List<String> extractRoles(Claims claims) {
        Object raw = claims.get(CLAIM_ROLES);
        if (raw == null) return List.of();

        if (!(raw instanceof List<?> list)) {
            throw new IllegalStateException("Invalid roles claim");
        }

        return list.stream()
                .map(String.class::cast)
                .collect(Collectors.toList());
    }

    private List<String> extractRoles(User user) {
        if (user.getRoles() == null) return List.of();
        return user.getRoles().stream()
                .map(r -> r.getName())
                .collect(Collectors.toList());
    }

    public boolean isRefreshToken(Jws<Claims> parsed) {
        return TokenType.from(parsed.getBody().get("typ", String.class))
                == TokenType.REFRESH;
    }

    private void validateSecret(String secret) {
        if (secret == null || secret.length() < 64) {
            throw new IllegalArgumentException(
                    "JWT secret must be at least 64 characters long"
            );
        }
    }
}
