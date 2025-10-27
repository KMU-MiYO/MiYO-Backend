package io.github.herbpot.miyobackend.domain.challenge.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * Mission Entity
 * - 미션 정의를 저장하는 엔티티
 * - Mission 테이블에 매핑
 */
@Entity
@Table(name = "Mission", indexes = {
    @Index(name = "idx_category_period", columnList = "category, start_date, end_date"),
    @Index(name = "idx_dates", columnList = "start_date, end_date")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Mission {

    /**
     * 미션 ID (Primary Key)
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "mission_id")
    private Long missionId;

    /**
     * 미션 이름
     */
    @Column(name = "title", nullable = false, length = 255)
    private String title;

    /**
     * 설명
     */
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    /**
     * 목표 횟수
     */
    @Column(name = "goal_count", nullable = false)
    private Integer goalCount;

    /**
     * 미션 종류 (proposal, empathy, comment 등)
     * - Strategy Pattern에서 사용할 카테고리
     */
    @Column(name = "category", nullable = false, length = 50)
    private String category;

    /**
     * 주간/월간 구분
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "period_type", nullable = false)
    private PeriodType periodType;

    /**
     * 미션 시작일
     */
    @Column(name = "start_date", nullable = false)
    private LocalDate startDate;

    /**
     * 미션 종료일
     */
    @Column(name = "end_date", nullable = false)
    private LocalDate endDate;

    /**
     * 완료 시 지급 포인트
     */
    @Column(name = "reward_points", nullable = false)
    private Integer rewardPoints = 0;

    /**
     * 생성 시각
     * - 자동으로 현재 시각 설정
     */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Builder 패턴을 사용한 생성자
     */
    @Builder
    public Mission(String title, String description, Integer goalCount,
                   String category, PeriodType periodType,
                   LocalDate startDate, LocalDate endDate, Integer rewardPoints) {
        this.title = title;
        this.description = description;
        this.goalCount = goalCount;
        this.category = category;
        this.periodType = periodType;
        this.startDate = startDate;
        this.endDate = endDate;
        this.rewardPoints = rewardPoints != null ? rewardPoints : 0;
    }

    /**
     * 주간/월간 구분 Enum
     */
    public enum PeriodType {
        weekly,   // 주간 미션
        monthly   // 월간 미션
    }
}
