package com.jaypal.authapp.exception.refresh;

public class RefreshTokenNotFoundException extends RefreshTokenException {
    public RefreshTokenNotFoundException() {
        super("Refresh token not found");
    }
}
