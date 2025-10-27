package io.github.herbpot.miyobackend.domain.challenge.dto;

import io.github.herbpot.miyobackend.domain.challenge.entity.UserMissionProgress;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 유저 미션 진행 현황 응답 DTO
 * - GET /v0/missions/progress API의 Response Body
 * - UserMissionProgress Entity로부터 생성
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserMissionProgressResponse {

    /**
     * 진행 상황 ID
     */
    private Long id;

    /**
     * 미션 ID
     */
    private Long missionId;

    /**
     * 미션 제목 (Optional - Mission join 시 추가)
     */
    private String missionTitle;

    /**
     * 유저 ID
     */
    private String userId;

    /**
     * 현재 수행 횟수
     */
    private Integer currentCount;

    /**
     * 목표 횟수 (Optional - Mission join 시 추가)
     */
    private Integer goalCount;

    /**
     * 완료 여부
     */
    private Boolean completed;

    /**
     * 완료 시각
     */
    private LocalDateTime completedAt;

    /**
     * 마지막 갱신 시각
     */
    private LocalDateTime updatedAt;

    /**
     * 진행률 (%) - 계산 필드
     */
    private Integer progressPercentage;

    /**
     * UserMissionProgress Entity로부터 UserMissionProgressResponse 생성
     */
    public static UserMissionProgressResponse from(UserMissionProgress progress) {
        return UserMissionProgressResponse.builder()
                .id(progress.getId())
                .missionId(progress.getMissionId())
                .userId(progress.getUserId())
                .currentCount(progress.getCurrentCount())
                .completed(progress.getCompleted())
                .completedAt(progress.getCompletedAt())
                .updatedAt(progress.getUpdatedAt())
                .build();
    }

    /**
     * 미션 정보를 포함한 UserMissionProgressResponse 생성
     */
    public static UserMissionProgressResponse withMissionInfo(UserMissionProgress progress,
                                                               String missionTitle,
                                                               Integer goalCount) {
        UserMissionProgressResponse response = from(progress);
        response.missionTitle = missionTitle;
        response.goalCount = goalCount;
        response.progressPercentage = calculateProgressPercentage(progress.getCurrentCount(), goalCount);
        return response;
    }

    /**
     * 진행률 계산
     */
    private static Integer calculateProgressPercentage(Integer currentCount, Integer goalCount) {
        if (goalCount == null || goalCount == 0) {
            return 0;
        }
        int percentage = (int) ((currentCount * 100.0) / goalCount);
        return Math.min(percentage, 100);  // 최대 100%
    }
}
