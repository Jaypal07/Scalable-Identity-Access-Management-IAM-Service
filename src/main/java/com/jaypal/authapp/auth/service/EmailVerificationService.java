package com.jaypal.authapp.auth.service;

import com.jaypal.authapp.auth.repositoty.EmailVerificationTokenRepository;
import com.jaypal.authapp.config.FrontendProperties;
import com.jaypal.authapp.exception.email.VerificationException;
import com.jaypal.authapp.infrastructure.email.EmailService;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.model.VerificationToken;
import com.jaypal.authapp.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final FrontendProperties frontendProperties;

    // ---------------- CREATE / RESEND ----------------

    @Transactional
    public void createVerificationToken(User user) {
        VerificationToken token = tokenRepository.findByUser(user)
                .orElseGet(() -> new VerificationToken(user));

        token.regenerate();
        tokenRepository.save(token);

        String verifyLink = frontendProperties.getBaseUrl()
                + "/email-verify?token=" + token.getToken();

        emailService.sendVerificationEmail(user.getEmail(), verifyLink);
    }

    @Transactional
    public void resendVerificationToken(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            if (!user.isEnabled()) {
                createVerificationToken(user);
            }
        });
    }

    // ---------------- VERIFY ----------------

    @Transactional
    public void verifyEmail(String tokenValue) {
        VerificationToken token = tokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new VerificationException("Invalid verification token"));

        if (token.isExpired()) {
            tokenRepository.delete(token);
            throw new VerificationException("Invalid verification token");
        }

        User user = token.getUser();
        user.enable();

        tokenRepository.delete(token);
        userRepository.save(user);
    }
}
