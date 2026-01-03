package com.jaypal.authapp.exception.refresh;

public class RefreshTokenUserMismatchException extends RefreshTokenException {
    public RefreshTokenUserMismatchException() {
        super("Refresh token user mismatch");
    }
}
