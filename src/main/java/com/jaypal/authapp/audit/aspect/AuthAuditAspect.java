package com.jaypal.authapp.audit.aspect;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.model.*;
import com.jaypal.authapp.audit.service.AuthAuditService;
import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.dto.TokenResponse;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.annotation.*;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Aspect
@Component
@RequiredArgsConstructor
public class AuthAuditAspect {

    private final AuthAuditService auditService;
    private final HttpServletRequest request;

    // ---------- SUCCESS ----------

    @AfterReturning(
            pointcut = "@annotation(authAudit)",
            returning = "result"
    )
    public void auditSuccess(AuthAudit authAudit, Object result) {

        UUID userId = extractUserId(result);
        if (userId == null) {
            userId = extractUserIdFromContext();
        }

        auditService.log(
                userId,
                authAudit.event(),
                authAudit.provider(),
                request,
                true,
                null
        );
    }

    // ---------- FAILURE ----------

    @AfterThrowing(
            pointcut = "@annotation(authAudit)",
            throwing = "ex"
    )
    public void auditFailure(AuthAudit authAudit, Throwable ex) {

        AuthAuditEvent event =
                switch (authAudit.event()) {
                    case LOGIN_SUCCESS -> AuthAuditEvent.LOGIN_FAILURE;
                    case OAUTH_LOGIN_SUCCESS -> AuthAuditEvent.OAUTH_LOGIN_FAILURE;
                    default -> authAudit.event();
                };

        AuthFailureReason reason = resolveFailureReason(event, ex);

        UUID userId = extractUserIdFromContext();

        auditService.log(
                userId,
                event,
                authAudit.provider(),
                request,
                false,
                reason
        );
    }


    // ---------- REASON RESOLUTION ----------

    private AuthFailureReason resolveFailureReason(
            AuthAuditEvent event,
            Throwable ex
    ) {

        // ---------- LOGIN ----------
        if (event == AuthAuditEvent.LOGIN_FAILURE
                || event == AuthAuditEvent.OAUTH_LOGIN_FAILURE) {

            if (ex instanceof BadCredentialsException) {
                return AuthFailureReason.INVALID_CREDENTIALS;
            }
            if (ex instanceof UsernameNotFoundException) {
                return AuthFailureReason.USER_NOT_FOUND;
            }
            if (ex instanceof DisabledException) {
                return AuthFailureReason.ACCOUNT_DISABLED;
            }
            if (ex instanceof LockedException) {
                return AuthFailureReason.ACCOUNT_LOCKED;
            }
        }

        // ---------- TOKEN ----------
        if (event == AuthAuditEvent.TOKEN_ROTATION
                || event == AuthAuditEvent.TOKEN_REFRESH) {

            if (ex instanceof ExpiredJwtException) {
                return AuthFailureReason.TOKEN_EXPIRED;
            }
            if (ex instanceof JwtException) {
                return AuthFailureReason.TOKEN_INVALID;
            }
            if (ex instanceof IllegalArgumentException) {
                return AuthFailureReason.TOKEN_INVALID;
            }
        }

        // ---------- REGISTER ----------
        if (event == AuthAuditEvent.REGISTER) {

            if (ex instanceof DataIntegrityViolationException) {
                return AuthFailureReason.EMAIL_ALREADY_EXISTS;
            }
            if (ex instanceof IllegalArgumentException) {
                return AuthFailureReason.VALIDATION_FAILED;
            }
        }

        return AuthFailureReason.SYSTEM_ERROR;
    }


    // ---------- HELPERS ----------

    private UUID extractUserId(Object result) {

        if (result instanceof ResponseEntity<?> response) {
            Object body = response.getBody();
            if (body instanceof TokenResponse tokenResponse) {
                return tokenResponse.user().id();
            }
        }

        if (result instanceof AuthLoginResult authResult) {
            return authResult.user().getId();
        }

        return null;
    }

    private UUID extractUserIdFromContext() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof AuthPrincipal principal) {
            return principal.getUserId();
        }
        return null;
    }
}
