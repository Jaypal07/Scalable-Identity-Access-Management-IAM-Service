package com.jaypal.authapp.infrastructure.email;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Override
    public void sendPasswordResetEmail(String to, String resetLink) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Reset your password");
        message.setText("""
                Click the link below to reset your password.
                This link will expire in 15 minutes.

                %s
                """.formatted(resetLink));

        mailSender.send(message);
    }

    @Override
    public void sendVerificationEmail(String to, String verifyLink) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Verify your email address");
        message.setText("""
                Welcome! 🎉

                Please verify your email address by clicking the link below:

                %s

                If you did not create this account, please ignore this email.
                """.formatted(verifyLink));

        mailSender.send(message);
    }
}

