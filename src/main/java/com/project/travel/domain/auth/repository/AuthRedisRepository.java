package com.project.travel.domain.auth.repository;


import java.util.Optional;

public interface AuthRedisRepository {

    void saveRefreshToken(String userId, String refreshToken);

    Optional<String> getUserIdFromRefreshToken(String refreshToken);

    void deleteRefreshToken(String refreshToken);
}
