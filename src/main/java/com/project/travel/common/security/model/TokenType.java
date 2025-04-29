package com.project.travel.common.security.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.Duration;

@Getter
@RequiredArgsConstructor
public enum TokenType {
    ACCESS(Duration.ofMinutes(30)),
    REFRESH(Duration.ofDays(14));

    private final Duration expiration;
}
