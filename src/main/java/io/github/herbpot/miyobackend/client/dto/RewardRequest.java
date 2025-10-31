package io.github.herbpot.miyobackend.client.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Reward 지급 요청 DTO
 * - user-service의 /v0/reward/insert API 호출 시 사용
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RewardRequest {

    /**
     * 사용자 ID
     */
    private String userId;

    /**
     * 지급할 리워드 포인트
     */
    private Integer reward;
}
