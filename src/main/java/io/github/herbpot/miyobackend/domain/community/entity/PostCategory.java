package io.github.herbpot.miyobackend.domain.community.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * 게시글 카테고리 Enum
 * - 각 게시글은 하나의 카테고리를 가짐
 * - description: 사용자에게 표시될 한글 설명
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
