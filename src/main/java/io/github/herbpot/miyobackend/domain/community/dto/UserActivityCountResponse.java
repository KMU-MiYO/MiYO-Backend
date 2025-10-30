package io.github.herbpot.miyobackend.domain.community.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 사용자 활동 개수 조회 응답 DTO
 * - 사용자의 게시글, 댓글, 공감 개수 조회 시 사용
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class UserActivityCountResponse {

    /**
     * 총 개수
     */
    private long count;

    /**
     * 정적 팩토리 메서드
     */
    public static UserActivityCountResponse of(long count) {
        return new UserActivityCountResponse(count);
    }
}
