package com.jaypal.authapp.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

public final class JwtUtils {

    private JwtUtils() {}

    public static SecretKey createKey(String secret) {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public static String buildToken(
            SecretKey key,
            String issuer,
            UUID subjectId,
            Map<String, Object> claims,
            long ttlSeconds
    ) {
        Instant now = Instant.now();

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(subjectId.toString())
                .setIssuer(issuer)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(ttlSeconds)))
                .addClaims(claims)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public static String buildRefreshToken(
            SecretKey key,
            String issuer,
            UUID subjectId,
            Map<String, Object> claims,
            long ttlSeconds,
            String jti
    ) {
        Instant now = Instant.now();

        return Jwts.builder()
                .setId(jti)
                .setSubject(subjectId.toString())
                .setIssuer(issuer)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(ttlSeconds)))
                .addClaims(claims)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    // 🔒 STRICT PARSE
    public static Jws<Claims> parse(
            SecretKey key,
            String expectedIssuer,
            String token
    ) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .requireIssuer(expectedIssuer)
                    .build()
                    .parseClaimsJws(token);
        } catch (ExpiredJwtException e) {
            throw new JwtException("Token expired");
        } catch (JwtException e) {
            throw new JwtException("Invalid JWT token");
        }
    }
}
