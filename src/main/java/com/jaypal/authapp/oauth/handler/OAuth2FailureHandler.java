package com.jaypal.authapp.oauth.handler;

import com.jaypal.authapp.config.FrontendProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2FailureHandler implements AuthenticationFailureHandler {

    private final FrontendProperties frontendProperties;

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException {

        Objects.requireNonNull(exception, "AuthenticationException must not be null");

        final String redirectUrl = frontendProperties.getFailureRedirect();
        Objects.requireNonNull(
                redirectUrl,
                "Frontend failure redirect must be configured"
        );

        log.warn(
                "OAuth2 authentication failure: {}",
                exception.getMessage(),
                exception
        );

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.sendRedirect(redirectUrl);
    }
}
