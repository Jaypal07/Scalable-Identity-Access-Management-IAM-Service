package com.jaypal.authapp.security.config;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig {

    /**
     * Spring Security 6.4+ throws AuthorizationDeniedException for @PreAuthorize.
     * This handler converts it into AccessDeniedException so that
     * HttpSecurity.accessDeniedHandler() is triggered and returns 403 JSON.
     */
    @Bean
    public MethodAuthorizationDeniedHandler methodAuthorizationDeniedHandler() {
        return (MethodInvocation invocation, AuthorizationResult result) -> {
            throw new AccessDeniedException("Access is denied");
        };
    }
}
