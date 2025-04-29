package com.project.travel.domain.auth.dto.response;

public record AuthReissueResponse(
        String accessToken,

        String refreshToken
) {
}
