package com.jaypal.authapp.audit.model;

public enum AuthFailureReason {

    // ---------- LOGIN ----------
    INVALID_CREDENTIALS,
    USER_NOT_FOUND,
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,

    // ---------- TOKEN ----------
    TOKEN_MISSING,
    TOKEN_INVALID,
    TOKEN_EXPIRED,
    TOKEN_REVOKED,

    // ---------- REGISTRATION ----------
    EMAIL_ALREADY_EXISTS,
    VALIDATION_FAILED,

    // ---------- PASSWORD ----------
    PASSWORD_POLICY_VIOLATION,
    RESET_TOKEN_INVALID,
    RESET_TOKEN_EXPIRED,

    // ---------- FALLBACK ----------
    SYSTEM_ERROR
}
