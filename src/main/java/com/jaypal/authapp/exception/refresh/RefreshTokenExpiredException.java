package com.jaypal.authapp.exception.refresh;

public class RefreshTokenExpiredException extends RefreshTokenException {
    public RefreshTokenExpiredException() {
        super("Refresh token expired");
    }
}
