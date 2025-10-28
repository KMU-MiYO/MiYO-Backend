package io.github.herbpot.miyobackend.domain.challenge.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * 게시글/공모전 카테고리 Enum
 */
@Getter
@RequiredArgsConstructor
public enum PostCategory {
    NATURE("자연"),
    CULTURE("문화"),
    TRAFFIC("교통"),
    RESIDENCE("주거"),
    COMMERCIAL("상권"),
    NIGHT("야간"),
    ENVIRONMENT("환경");

    private final String description;
}
