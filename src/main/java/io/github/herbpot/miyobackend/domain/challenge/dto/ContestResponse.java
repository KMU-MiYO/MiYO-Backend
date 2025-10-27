package io.github.herbpot.miyobackend.domain.challenge.dto;

import io.github.herbpot.miyobackend.domain.challenge.entity.ContestData;
import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * 공모전 조회 응답 DTO
 * - GET /v0/contests API의 Response Body
 * - ContestData Entity로부터 생성
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ContestResponse {

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
     * 설명
     */
    private String description;

    /**
     * 시작일
     */
    private LocalDate startDate;

    /**
     * 종료일
     */
    private LocalDate endDate;

    /**
     * 1등 포인트
     */
    private Integer reward1st;

    /**
     * 2등 포인트
     */
    private Integer reward2nd;

    /**
     * 3등 포인트
     */
    private Integer reward3rd;

    /**
     * 보상 설명
     */
    private String rewardDescription;

    /**
     * 썸네일 URL
     */
    private String thumbnailUrl;

    /**
     * 생성 시각
     */
    private LocalDateTime createdAt;

    /**
     * 참가자 수 (Optional)
     */
    private Long participantCount;

    /**
     * 제출물 수 (Optional)
     */
    private Long submissionCount;

    /**
     * 사용자의 참가 여부 (Optional)
     */
    private Boolean isParticipant;

    /**
     * ContestData Entity로부터 ContestResponse 생성
     */
    public static ContestResponse from(ContestData contestData) {
        return ContestResponse.builder()
                .contestId(contestData.getContestId())
                .title(contestData.getTitle())
                .host(contestData.getHost())
                .description(contestData.getDescription())
                .startDate(contestData.getStartDate())
                .endDate(contestData.getEndDate())
                .reward1st(contestData.getReward1st())
                .reward2nd(contestData.getReward2nd())
                .reward3rd(contestData.getReward3rd())
                .rewardDescription(contestData.getRewardDescription())
                .thumbnailUrl(contestData.getThumbnailUrl())
                .createdAt(contestData.getCreatedAt())
                .build();
    }

    /**
     * 통계 정보를 포함한 ContestResponse 생성
     */
    public static ContestResponse withStats(ContestData contestData, Long participantCount, Long submissionCount) {
        ContestResponse response = from(contestData);
        response.participantCount = participantCount;
        response.submissionCount = submissionCount;
        return response;
    }

    /**
     * 사용자 참가 여부를 포함한 ContestResponse 생성
     */
    public static ContestResponse withParticipation(ContestData contestData, Boolean isParticipant) {
        ContestResponse response = from(contestData);
        response.isParticipant = isParticipant;
        return response;
    }
}
