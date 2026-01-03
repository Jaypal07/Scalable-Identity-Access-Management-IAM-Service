package com.jaypal.authapp.exception.refresh;

public abstract class RefreshTokenException extends RuntimeException {

    protected RefreshTokenException(String message) {
        super(message);
    }
}
