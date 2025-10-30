package io.github.herbpot.miyobackend.domain.community.entity.mission;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

/**
 * UserMissionProgress Entity
 * - 유저별 미션 진행 현황을 저장하는 엔티티
 */
@Entity
@Table(name = "user_mission_progress", indexes = {
    @Index(name = "idx_user_mission", columnList = "user_id, mission_id"),
    @Index(name = "idx_user_id", columnList = "user_id")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserMissionProgress {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "mission_id", nullable = false)
    private Long missionId;

    @Column(name = "user_id", nullable = false, length = 255)
    private String userId;

    @Column(name = "current_count", nullable = false)
    private Integer currentCount = 0;

    @Column(name = "completed", nullable = false)
    private Boolean completed = false;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Builder
    public UserMissionProgress(Long missionId, String userId,
                               Integer currentCount, Boolean completed,
                               LocalDateTime completedAt) {
        this.missionId = missionId;
        this.userId = userId;
        this.currentCount = currentCount != null ? currentCount : 0;
        this.completed = completed != null ? completed : false;
        this.completedAt = completedAt;
    }

    /**
     * 초기 진행 상태 생성
     */
    public static UserMissionProgress createInitial(Long missionId, String userId) {
        return UserMissionProgress.builder()
                .missionId(missionId)
                .userId(userId)
                .currentCount(0)
                .completed(false)
                .build();
    }

    /**
     * 진행 횟수 증가
     */
    public void incrementProgress(Integer goalCount) {
        this.currentCount++;
        if (this.currentCount >= goalCount && !this.completed) {
            this.completed = true;
            this.completedAt = LocalDateTime.now();
        }
    }

    /**
     * 진행 현황 리셋
     */
    public void reset() {
        this.currentCount = 0;
        this.completed = false;
        this.completedAt = null;
    }
}
