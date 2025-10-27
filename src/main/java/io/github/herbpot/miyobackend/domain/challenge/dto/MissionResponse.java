package io.github.herbpot.miyobackend.domain.challenge.dto;

import io.github.herbpot.miyobackend.domain.challenge.entity.Mission;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * 미션 조회 응답 DTO
 * - GET /v0/missions API의 Response Body
 * - Mission Entity로부터 생성
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MissionResponse {

    /**
     * 미션 ID
     */
    private Long missionId;

    /**
     * 미션 이름
     */
    private String title;

    /**
     * 설명
     */
    private String description;

    /**
     * 목표 횟수
     */
    private Integer goalCount;

    /**
     * 미션 종류
     */
    private String category;

    /**
     * 주간/월간 구분
     */
    private Mission.PeriodType periodType;

    /**
     * 미션 시작일
     */
    private LocalDate startDate;

    /**
     * 미션 종료일
     */
    private LocalDate endDate;

    /**
     * 완료 시 지급 포인트
     */
    private Integer rewardPoints;

    /**
     * 생성 시각
     */
    private LocalDateTime createdAt;

    /**
     * 사용자의 현재 진행 횟수 (Optional)
     */
    private Integer currentCount;

    /**
     * 사용자의 완료 여부 (Optional)
     */
    private Boolean completed;

    /**
     * Mission Entity로부터 MissionResponse 생성
     */
    public static MissionResponse from(Mission mission) {
        return MissionResponse.builder()
                .missionId(mission.getMissionId())
                .title(mission.getTitle())
                .description(mission.getDescription())
                .goalCount(mission.getGoalCount())
                .category(mission.getCategory())
                .periodType(mission.getPeriodType())
                .startDate(mission.getStartDate())
                .endDate(mission.getEndDate())
                .rewardPoints(mission.getRewardPoints())
                .createdAt(mission.getCreatedAt())
                .build();
    }

    /**
     * 사용자 진행 현황을 포함한 MissionResponse 생성
     */
    public static MissionResponse withProgress(Mission mission, Integer currentCount, Boolean completed) {
        MissionResponse response = from(mission);
        response.currentCount = currentCount;
        response.completed = completed;
        return response;
    }
}
