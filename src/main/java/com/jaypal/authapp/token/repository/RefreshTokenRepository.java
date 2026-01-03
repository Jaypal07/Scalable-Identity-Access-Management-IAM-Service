package com.jaypal.authapp.token.repository;

import com.jaypal.authapp.token.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByJti(String jti);

    @Query("""
        select rt
        from RefreshToken rt
        join fetch rt.user u
        join fetch u.roles
        where rt.jti = :jti
    """)
    Optional<RefreshToken> findByJtiWithUserAndRoles(@Param("jti") String jti);

    @Modifying
    @Query("""
        update RefreshToken rt
        set rt.revoked = true
        where rt.user.id = :userId
          and rt.revoked = false
    """)
    void revokeAllActiveByUserId(@Param("userId") UUID userId);
}

