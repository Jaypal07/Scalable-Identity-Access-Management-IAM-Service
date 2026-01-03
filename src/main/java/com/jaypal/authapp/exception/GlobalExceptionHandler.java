package com.jaypal.authapp.exception;

import com.jaypal.authapp.exception.email.AlreadyVerifiedException;
import com.jaypal.authapp.exception.email.VerificationException;
import com.jaypal.authapp.exception.refresh.RefreshTokenException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";

    // ---------------------------------------------------------
    // RFC 7807 RESPONSE BUILDER
    // ---------------------------------------------------------

    private ResponseEntity<Map<String, Object>> problem(
            HttpStatus status,
            String title,
            String detail,
            WebRequest request,
            String logMessage,
            Throwable ex,
            boolean logStackTrace
    ) {
        String correlationId = UUID.randomUUID().toString();
        String path = extractPath(request);

        if (logStackTrace) {
            log.error("{} | correlationId={}", logMessage, correlationId, ex);
        } else {
            log.warn("{} | correlationId={}", logMessage, correlationId);
        }

        Map<String, Object> body = new HashMap<>();
        body.put("type", URI.create("about:blank"));
        body.put("title", title);
        body.put("status", status.value());
        body.put("detail", detail);
        body.put("instance", path);
        body.put("correlationId", correlationId);
        body.put("timestamp", Instant.now().toString());

        return ResponseEntity
                .status(status)
                .header(CORRELATION_HEADER, correlationId)
                .body(body);
    }

    private String extractPath(WebRequest request) {
        if (request instanceof ServletWebRequest servletRequest) {
            return servletRequest.getRequest().getRequestURI();
        }
        return "N/A";
    }

    // ---------------------------------------------------------
    // AUTHENTICATION
    // ---------------------------------------------------------

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<Map<String, Object>> handleDisabled(
            DisabledException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.FORBIDDEN,
                "Account disabled",
                "Please verify your email address before logging in.",
                request,
                "Authentication failure: account disabled",
                ex,
                false
        );
    }

    @ExceptionHandler({
            BadCredentialsException.class,
            UsernameNotFoundException.class,
            LockedException.class
    })
    public ResponseEntity<Map<String, Object>> handleAuthFailures(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.UNAUTHORIZED,
                "Authentication failed",
                "Invalid username or password.",
                request,
                "Authentication failure: " + ex.getClass().getSimpleName(),
                ex,
                false
        );
    }

    // ---------------------------------------------------------
    // AUTHORIZATION
    // ---------------------------------------------------------

    @ExceptionHandler({
            AccessDeniedException.class,
            AuthorizationDeniedException.class
    })
    public ResponseEntity<Map<String, Object>> handleAccessDenied(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.FORBIDDEN,
                "Access denied",
                "You do not have permission to access this resource.",
                request,
                "Authorization failure: " + ex.getClass().getSimpleName(),
                ex,
                false
        );
    }

    // ---------------------------------------------------------
    // BUSINESS
    // ---------------------------------------------------------

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNotFound(
            ResourceNotFoundException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.NOT_FOUND,
                "Resource not found",
                ex.getMessage(),
                request,
                "Resource not found",
                ex,
                false
        );
    }

    @ExceptionHandler(VerificationException.class)
    public ResponseEntity<Map<String, Object>> handleVerification(
            VerificationException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "Verification failed",
                ex.getMessage(),
                request,
                "Verification failure",
                ex,
                false
        );
    }

    @ExceptionHandler(AlreadyVerifiedException.class)
    public ResponseEntity<Map<String, Object>> handleAlreadyVerified(
            AlreadyVerifiedException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.CONFLICT,
                "Account already verified",
                ex.getMessage(),
                request,
                "Account already verified",
                ex,
                false
        );
    }

    @ExceptionHandler(RefreshTokenException.class)
    public ResponseEntity<Map<String, Object>> handleRefreshTokenFailure(
            RefreshTokenException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.UNAUTHORIZED,
                "Invalid refresh token",
                "Your session has expired. Please log in again.",
                request,
                "Refresh token validation failed: " + ex.getClass().getSimpleName(),
                ex,
                false
        );
    }

    // ---------------------------------------------------------
    // VALIDATION
    // ---------------------------------------------------------

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(
            MethodArgumentNotValidException ex,
            WebRequest request
    ) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }

        return problem(
                HttpStatus.BAD_REQUEST,
                "Validation failed",
                errors.toString(),
                request,
                "Validation failure",
                ex,
                false
        );
    }

    // ---------------------------------------------------------
    // DATA INTEGRITY (POSTGRES + HIBERNATE)
    // ---------------------------------------------------------

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> handleDataIntegrity(
            DataIntegrityViolationException ex,
            WebRequest request
    ) {
        // 1. Hibernate constraint violation
        Throwable cause = ex.getCause();
        if (cause instanceof org.hibernate.exception.ConstraintViolationException cve) {
            String constraint = cve.getConstraintName();

            if ("users_email".equalsIgnoreCase(constraint)) {
                return problem(
                        HttpStatus.CONFLICT,
                        "Email already exists",
                        "An account with this email address already exists.",
                        request,
                        "Duplicate email constraint violation (Hibernate)",
                        ex,
                        false
                );
            }
        }

        // 2. JDBC SQLState fallback (portable)
        Throwable root = ex.getRootCause();
        if (root instanceof java.sql.SQLException sqlEx) {
            if ("23505".equals(sqlEx.getSQLState())) {
                return problem(
                        HttpStatus.CONFLICT,
                        "Email already exists",
                        "An account with this email address already exists.",
                        request,
                        "Duplicate email constraint violation (SQLState 23505)",
                        ex,
                        false
                );
            }
        }

        // 3. Fallback
        return problem(
                HttpStatus.BAD_REQUEST,
                "Invalid request",
                "Request violates data constraints.",
                request,
                "Unhandled data integrity violation",
                ex,
                false
        );
    }


    // ---------------------------------------------------------
    // FALLBACK
    // ---------------------------------------------------------

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal server error",
                "An unexpected error occurred.",
                request,
                "Unhandled exception",
                ex,
                true
        );
    }
}
