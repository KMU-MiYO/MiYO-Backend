package io.github.herbpot.miyobackend.domain.community.entity.mission;

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
 */
@Entity
@Table(name = "mission", indexes = {
    @Index(name = "idx_category_dates", columnList = "category, start_date, end_date"),
    @Index(name = "idx_dates", columnList = "start_date, end_date")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Mission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "mission_id")
    private Long missionId;

    @Column(name = "title", nullable = false, length = 255)
    private String title;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "goal_count", nullable = false)
    private Integer goalCount;

    /**
     * 미션 카테고리: proposal, empathy, comment
     */
    @Column(name = "category", nullable = false, length = 50)
    private String category;

    @Enumerated(EnumType.STRING)
    @Column(name = "period_type", nullable = false)
    private PeriodType periodType;

    @Column(name = "start_date", nullable = false)
    private LocalDate startDate;

    @Column(name = "end_date", nullable = false)
    private LocalDate endDate;

    @Column(name = "reward_points", nullable = false)
    private Integer rewardPoints = 0;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

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

    public enum PeriodType {
        weekly,
        monthly
    }
}
