package com.jaypal.authapp.user.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(
        name = "users",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "jk_users_provider_provider_id",
                        columnNames = {"provider", "provider_id"}
                ),
                @UniqueConstraint(
                        name = "users_email",
                        columnNames = {"email"}
                )
        }
)
@Getter
@Setter(AccessLevel.PRIVATE)
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID id;

    @Column(nullable = false)
    private String email;

    private String password;

    @Column(nullable = false)
    private String name;

    private String image;

    @Column(nullable = false)
    private boolean enabled;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Provider provider;

    @Column(name = "provider_id", nullable = false)
    private String providerId;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    // ---------------- FACTORIES ----------------

    public static User createLocal(String email, String password, String name) {
        UUID id = UUID.randomUUID();
        Instant now = Instant.now();

        return User.builder()
                .id(id)
                .email(email)
                .password(password)
                .name(name)
                .enabled(false)
                .provider(Provider.LOCAL)
                .providerId(id.toString())
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    public static User createOAuth(
            Provider provider,
            String providerId,
            String email,
            String name,
            String image
    ) {
        UUID id = UUID.randomUUID();
        Instant now = Instant.now();

        return User.builder()
                .id(id)
                .email(email)
                .name(name)
                .image(image)
                .enabled(true)
                .provider(provider)
                .providerId(providerId)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    // ---------------- DOMAIN ----------------

    public void enable() {
        this.enabled = true;
        this.updatedAt = Instant.now();
    }

    public void disable() {
        this.enabled = false;
        this.updatedAt = Instant.now();
    }

    public void changePassword(String encodedPassword) {
        this.password = encodedPassword;
        this.updatedAt = Instant.now();
    }

    public void updateProfile(String name, String image) {
        if (name != null) this.name = name;
        if (image != null) this.image = image;
        this.updatedAt = Instant.now();
    }

    public void setRoles(Set<Role> roles) {
        this.roles.clear();
        this.roles.addAll(roles);
        this.updatedAt = Instant.now();
    }
}
