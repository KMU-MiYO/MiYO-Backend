package io.github.herbpot.miyobackend.domain.challenge.entity;

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
 * - UserMissionProgress 테이블에 매핑
 * - 복합키 (mission_id, user_id) 사용
 */
@Entity
@Table(name = "UserMissionProgress", indexes = {
    @Index(name = "idx_user_id", columnList = "user_id")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserMissionProgress {

    /**
     * 진행 상황 ID (Primary Key)
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    /**
     * 미션 ID
     */
    @Column(name = "mission_id", nullable = false)
    private Long missionId;

    /**
     * 유저 ID
     */
    @Column(name = "user_id", nullable = false, length = 255)
    private String userId;

    /**
     * 현재 수행 횟수
     */
    @Column(name = "current_count", nullable = false)
    private Integer currentCount = 0;

    /**
     * 완료 여부
     */
    @Column(name = "completed", nullable = false)
    private Boolean completed = false;

    /**
     * 완료 시각
     */
    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    /**
     * 마지막 갱신 시각
     * - 자동으로 갱신 시각 설정
     */
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    /**
     * Builder 패턴을 사용한 생성자
     */
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
     * 정적 팩토리 메서드
     * - missionId와 userId를 받아 초기 진행 현황 생성
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
     * @param goalCount 목표 횟수 (완료 여부 판단용)
     */
    public void incrementProgress(Integer goalCount) {
        this.currentCount++;
        if (this.currentCount >= goalCount && !this.completed) {
            this.completed = true;
            this.completedAt = LocalDateTime.now();
        }
    }

    /**
     * 진행 현황 리셋 (주간/월간 미션 갱신 시)
     */
    public void reset() {
        this.currentCount = 0;
        this.completed = false;
        this.completedAt = null;
    }
}
