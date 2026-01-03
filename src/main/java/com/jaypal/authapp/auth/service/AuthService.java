package com.jaypal.authapp.auth.service;

import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.event.UserRegisteredEvent;
import com.jaypal.authapp.auth.repositoty.PasswordResetTokenRepository;
import com.jaypal.authapp.config.FrontendProperties;
import com.jaypal.authapp.dto.UserCreateRequest;
import com.jaypal.authapp.infrastructure.email.EmailService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.service.RefreshTokenService;
import com.jaypal.authapp.auth.model.PasswordResetToken;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import com.jaypal.authapp.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final UserService userService;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final FrontendProperties frontendProperties;
    private final EmailVerificationService  emailVerificationService;
    private final ApplicationEventPublisher eventPublisher;


    @Transactional
    public void register(UserCreateRequest request) {
        User user = userService.createAndReturnDomainUser(request);

        // Publish event. No email sent here.
        eventPublisher.publishEvent(new UserRegisteredEvent(user));
    }


    @Transactional
    public AuthLoginResult issueTokens(User user) {

        RefreshToken refreshToken =
                refreshTokenService.issue(
                        user,
                        jwtService.getRefreshTtlSeconds()
                );

        return new AuthLoginResult(
                user,
                jwtService.generateAccessToken(user),
                jwtService.generateRefreshToken(
                        user,
                        refreshToken.getJti()
                ),
                jwtService.getRefreshTtlSeconds()
        );
    }


    @Transactional
    public AuthLoginResult login(AuthPrincipal principal) {

        User user = userRepository.findById(principal.getUserId())
                .orElseThrow(() ->
                        new IllegalStateException(
                                "Authenticated user not found"
                        ));

        RefreshToken refreshToken =
                refreshTokenService.issue(
                        user,
                        jwtService.getRefreshTtlSeconds()
                );

        return new AuthLoginResult(
                user,
                jwtService.generateAccessToken(user),
                jwtService.generateRefreshToken(
                        user,
                        refreshToken.getJti()
                ),
                jwtService.getRefreshTtlSeconds()
        );
    }

    @Transactional
    public void initiatePasswordReset(String email) {
        log.info("Password reset requested for: {}", email);

        userRepository.findByEmail(email).ifPresentOrElse(user -> {
            // Clear old tokens
            passwordResetTokenRepository.deleteAllByUser_Id(user.getId());

            String tokenValue = UUID.randomUUID().toString();
            PasswordResetToken token = PasswordResetToken.builder()
                    .token(tokenValue)
                    .user(user)
                    .expiresAt(Instant.now().plusSeconds(900)) // 15 mins
                    .build();

            passwordResetTokenRepository.save(token);

            String resetLink = frontendProperties.getBaseUrl()+"/reset-password?token=" + tokenValue;

            try {
                emailService.sendPasswordResetEmail(user.getEmail(), resetLink);
                log.info("Reset email sent successfully to {}", email);
            } catch (Exception e) {
                log.error("Failed to send email to {}: {}", email, e.getMessage());
            }
        }, () -> log.warn("Reset requested for non-existent email: {}", email));
    }


    @Transactional
    public void resetPassword(String tokenValue, String rawPassword) {
        if (rawPassword == null || rawPassword.length() < 8) {
            throw new IllegalArgumentException("Password too short");
        }

        PasswordResetToken token = passwordResetTokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new BadCredentialsException("Invalid reset token"));

        if (token.isUsed() || token.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Reset token expired or already used");
        }

        User user = token.getUser();
        user.changePassword(passwordEncoder.encode(rawPassword));
        token.setUsed(true);

        userRepository.save(user);
        passwordResetTokenRepository.save(token);
        log.info("Password successfully updated for user: {}", user.getEmail());
    }


}
