package com.jaypal.authapp.audit.validation;

import com.jaypal.authapp.audit.model.AuthAuditEvent;
import com.jaypal.authapp.audit.model.AuthFailureReason;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

public final class AuthAuditMatrix {

    private static final Map<AuthAuditEvent, Set<AuthFailureReason>> MATRIX =
            new EnumMap<>(AuthAuditEvent.class);

    static {
        // LOGIN
        MATRIX.put(
                AuthAuditEvent.LOGIN_FAILURE,
                EnumSet.of(
                        AuthFailureReason.INVALID_CREDENTIALS,
                        AuthFailureReason.USER_NOT_FOUND,
                        AuthFailureReason.ACCOUNT_DISABLED,
                        AuthFailureReason.ACCOUNT_LOCKED
                )
        );

        // OAUTH
        MATRIX.put(
                AuthAuditEvent.OAUTH_LOGIN_FAILURE,
                EnumSet.of(
                        AuthFailureReason.INVALID_CREDENTIALS,
                        AuthFailureReason.ACCOUNT_DISABLED
                )
        );

        // TOKEN
        MATRIX.put(
                AuthAuditEvent.TOKEN_ROTATION,
                EnumSet.of(
                        AuthFailureReason.TOKEN_INVALID,
                        AuthFailureReason.TOKEN_EXPIRED,
                        AuthFailureReason.TOKEN_REVOKED
                )
        );

        // REGISTER
        MATRIX.put(
                AuthAuditEvent.REGISTER,
                EnumSet.of(
                        AuthFailureReason.EMAIL_ALREADY_EXISTS,
                        AuthFailureReason.VALIDATION_FAILED
                )
        );
    }

    private AuthAuditMatrix() {}

    public static boolean isAllowed(
            AuthAuditEvent event,
            AuthFailureReason reason
    ) {
        if (reason == null) {
            return true;
        }

        if (reason == AuthFailureReason.SYSTEM_ERROR) {
            return true;
        }

        Set<AuthFailureReason> allowed = MATRIX.get(event);
        return allowed != null && allowed.contains(reason);
    }
}
