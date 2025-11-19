package com.example.auth.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.SignatureException;


@Component
public class JwtAuthEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException)
            throws IOException {

        Throwable cause = (Throwable) request.getAttribute("jwt_exception");

        // unwrap nested exceptions
        if (cause != null && cause.getCause() != null) {
            cause = cause.getCause();
        }

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        if (cause instanceof ExpiredJwtException) {
            response.getWriter().write("{\"error\": \"JWT token expired\"}");
        } else if (cause instanceof SignatureException) {
            response.getWriter().write("{\"error\": \"Invalid JWT signature\"}");
        } else if (cause instanceof MalformedJwtException) {
            response.getWriter().write("{\"error\": \"Malformed JWT token\"}");
        } else if (cause != null) {
            response.getWriter().write("{\"error\": \"" + cause.getMessage() + "\"}");
        } else {
            response.getWriter().write("{\"error\": \"Missing or invalid JWT token\"}");
        }
    }
}
