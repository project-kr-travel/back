package com.project.travel.domain.auth.repository;

import com.project.travel.common.security.model.TokenType;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class AuthRedisRepositoryImpl implements AuthRedisRepository {

    private final RedisTemplate<String, String> redisTemplate;

    private final String REFRESH_TOKEN_PREFIX = "RT:";

    @Override
    public void saveRefreshToken(String userId, String refreshToken) {
        redisTemplate.opsForValue().set(
                REFRESH_TOKEN_PREFIX + refreshToken,
                userId,
                TokenType.REFRESH.getExpiration()
        );
    }

    @Override
    public Optional<String> getUserIdFromRefreshToken(String refreshToken) {
        return Optional.ofNullable(redisTemplate.opsForValue().get(REFRESH_TOKEN_PREFIX + refreshToken));
    }

    @Override
    public void deleteRefreshToken(String refreshToken) {
        redisTemplate.delete(REFRESH_TOKEN_PREFIX + refreshToken);
    }
}
