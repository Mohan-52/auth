package com.example.auth.security;


import com.example.auth.exception.JwtAuthenticationException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.DecodingException;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil {
    private final String JWT_SECRECT="secrectsecrectsecrectsecrectsecrectsecrectsecrectsecrectsecrectsecrect";
    private final Long EXPIRATION_MS= 10L * 24 * 60 * 60 * 1000;

    public String generateToken(String email){
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+EXPIRATION_MS))
                .signWith(SignatureAlgorithm.HS256, JWT_SECRECT)
                .compact();
    }

    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(JWT_SECRECT)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new JwtAuthenticationException("JWT token has expired", e);
        } catch (MalformedJwtException e) {
            throw new JwtAuthenticationException("JWT token is malformed", e);
        } catch (SignatureException e) {
            throw new JwtAuthenticationException("JWT signature is invalid", e);
        } catch (DecodingException e) {
            throw new JwtAuthenticationException("JWT token format is corrupted", e);
        } catch (JwtException e) {
            throw new JwtAuthenticationException("Invalid JWT token", e);
        }
    }



    public String extractEmail(String token){
        return extractAllClaims(token).getSubject();
    }

    public boolean isTokenValid(String token){
        try {
            extractAllClaims(token);
            return true;
        }catch (JwtException ex){
            return false;
        }
    }

}
