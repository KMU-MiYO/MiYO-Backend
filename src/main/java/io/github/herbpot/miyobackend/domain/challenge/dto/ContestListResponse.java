package io.github.herbpot.miyobackend.domain.challenge.dto;

import io.github.herbpot.miyobackend.domain.challenge.entity.ContestData;
import io.github.herbpot.miyobackend.domain.challenge.entity.PostCategory;
import lombok.*;

/**
 * 공모전 목록 조회 응답 DTO
 * - GET /v0/contests API의 Response Body (목록)
 * - 최소한의 정보만 포함 (contestId, title, host, category)
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ContestListResponse {

    /**
     * 공모전 ID
     */
    private Long contestId;

    /**
     * 공모전 제목
     */
    private String title;

    /**
     * 주관 기관
     */
    private String host;

    /**
     * 카테고리
     */
    private PostCategory category;

    /**
     * ContestData Entity로부터 ContestListResponse 생성
     */
    public static ContestListResponse from(ContestData contestData) {
        return ContestListResponse.builder()
                .contestId(contestData.getContestId())
                .title(contestData.getTitle())
                .host(contestData.getHost())
                .category(contestData.getCategory())
                .build();
    }
}
