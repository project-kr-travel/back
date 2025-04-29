package com.project.travel.common.security;

import com.project.travel.common.security.error.SecurityErrorCode;
import com.project.travel.common.security.model.TokenType;
import com.project.travel.domain.user.entity.User;
import com.project.travel.domain.user.entity.UserRole;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenProvider {

    private final String BEARER_PREFIX = "Bearer ";
    private final SecretKey accessTokenSecretKey;
    private final SecretKey refreshTokenSecretKey;

    public JwtTokenProvider(
            @Value("${spring.jwt.secret.access}") String accessSecretKey,
            @Value("${spring.jwt.secret.refresh}") String refreshSecretKey
    ) {
        this.accessTokenSecretKey = new SecretKeySpec(
                accessSecretKey.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS512.key().build().getAlgorithm()
        );
        this.refreshTokenSecretKey = new SecretKeySpec(
                refreshSecretKey.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS512.key().build().getAlgorithm()
        );
    }

    public String generateAccessToken(String userId, String role) {
        Date now = new Date();

        return Jwts.builder()
                .claim("id", userId)
                .claim("role", role)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + TokenType.ACCESS.getExpiration().toMillis()))
                .signWith(accessTokenSecretKey)
                .compact();
    }

    public String generateRefreshToken() {
        Date now = new Date();

        return Jwts.builder()
                .issuedAt(now)
                .expiration(new Date(now.getTime() + TokenType.REFRESH.getExpiration().toMillis()))
                .signWith(refreshTokenSecretKey)
                .compact();
    }

    public boolean validateToken(String token, TokenType tokenType) {
        SecretKey tokenSecretKey;

        if (tokenType.equals(TokenType.ACCESS)) {
            validateAccessTokenStartsWithBearer(token);

            tokenSecretKey = accessTokenSecretKey;
            token = removeBearer(token);
        } else {
            tokenSecretKey = refreshTokenSecretKey;
        }

        try {
            return Jwts.parser()
                    .verifyWith(tokenSecretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getExpiration()
                    .after(new Date());
        } catch (SecurityException | MalformedJwtException e) {
            log.error(SecurityErrorCode.INVALID_JWT_SIGNATURE.getMessage());
        } catch (ExpiredJwtException e) {
            log.error(SecurityErrorCode.EXPIRED_JWT_TOKEN.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error(SecurityErrorCode.UNSUPPORTED_JWT_TOKEN.getMessage());
        } catch (Exception e) {
            log.error(SecurityErrorCode.INVALID_JWT_TOKEN.getMessage());
        }

        return false;
    }

    public User getUserFromToken(String token) {
        String accessToken = removeBearer(token);
        Claims claims = parseClaimsFromToken(accessToken);

        return User.builder()
                .id(Long.parseLong(claims.get("id", String.class)))
                .role(UserRole.of(claims.get("role", String.class)))
                .build();
    }

    public long getAccessTokenExpiryTime(String token) {
        Claims claims = parseClaimsFromToken(token);
        return claims.getExpiration().getTime();
    }

    private void validateAccessTokenStartsWithBearer(String token) {
        if (!token.startsWith(BEARER_PREFIX)) {
            throw new BadCredentialsException(SecurityErrorCode.INVALID_TOKEN.getMessage());
        }
    }

    private Claims parseClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(accessTokenSecretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private String removeBearer(String token) {
        return token.substring("Bearer ".length());
    }
}
