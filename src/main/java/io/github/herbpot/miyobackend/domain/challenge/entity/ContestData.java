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
 * ContestData Entity
 * - 공모전 메타데이터를 저장하는 엔티티
 * - ContestData 테이블에 매핑
 */
@Entity
@Table(name = "ContestData", indexes = {
    @Index(name = "idx_dates", columnList = "start_date, end_date")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ContestData {

    /**
     * 공모전 ID (Primary Key)
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "contest_id")
    private Long contestId;

    /**
     * 공모전 제목
     */
    @Column(name = "title", nullable = false, length = 255)
    private String title;

    /**
     * 주관 기관
     */
    @Column(name = "host", length = 100)
    private String host;

    /**
     * 카테고리
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "category", length = 20, nullable = false)
    private PostCategory category;

    /**
     * 설명
     */
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    /**
     * 시작일
     */
    @Column(name = "start_date", nullable = false)
    private LocalDate startDate;

    /**
     * 종료일
     */
    @Column(name = "end_date", nullable = false)
    private LocalDate endDate;

    /**
     * 1등 포인트
     */
    @Column(name = "reward_1st")
    private Integer reward1st;

    /**
     * 2등 포인트
     */
    @Column(name = "reward_2nd")
    private Integer reward2nd;

    /**
     * 3등 포인트
     */
    @Column(name = "reward_3rd")
    private Integer reward3rd;

    /**
     * 보상 설명
     */
    @Column(name = "reward_description", columnDefinition = "TEXT")
    private String rewardDescription;

    /**
     * 썸네일 이미지 URL
     */
    @Column(name = "thumbnail_url", length = 255)
    private String thumbnailUrl;

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
    public ContestData(String title, String host, PostCategory category, String description,
                       LocalDate startDate, LocalDate endDate,
                       Integer reward1st, Integer reward2nd, Integer reward3rd,
                       String rewardDescription, String thumbnailUrl) {
        this.title = title;
        this.host = host;
        this.category = category;
        this.description = description;
        this.startDate = startDate;
        this.endDate = endDate;
        this.reward1st = reward1st;
        this.reward2nd = reward2nd;
        this.reward3rd = reward3rd;
        this.rewardDescription = rewardDescription;
        this.thumbnailUrl = thumbnailUrl;
    }
}
