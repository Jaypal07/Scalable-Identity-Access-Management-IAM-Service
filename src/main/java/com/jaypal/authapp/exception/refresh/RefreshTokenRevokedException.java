package com.jaypal.authapp.exception.refresh;

public class RefreshTokenRevokedException extends RefreshTokenException {
    public RefreshTokenRevokedException() {
        super("Refresh token revoked");
    }
}
