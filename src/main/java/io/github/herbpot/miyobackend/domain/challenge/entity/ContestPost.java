package io.github.herbpot.miyobackend.domain.challenge.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * ContestPost Entity
 * - 공모전 제출물을 저장하는 엔티티
 * - ContestPost 테이블에 매핑
 * - 1인 1제출 제약: UNIQUE KEY (contest_id, user_id)
 */
@Entity
@Table(name = "ContestPost",
    indexes = {
        @Index(name = "idx_contest_id", columnList = "contest_id")
    },
    uniqueConstraints = {
        @UniqueConstraint(name = "unique_contest_user", columnNames = {"contest_id", "user_id"})
    }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ContestPost {

    /**
     * 제출물 ID (Primary Key)
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    /**
     * 공모전 ID
     * - ContestData 참조
     */
    @Column(name = "contest_id", nullable = false)
    private Long contestId;

    /**
     * 부모 게시글 ID
     * - null이면 원본 제출물, 값이 있으면 댓글
     */
    @Column(name = "parent_post_id")
    private Long parentPostId;

    /**
     * 작성자 ID
     */
    @Column(name = "user_id", nullable = false, length = 255)
    private String userId;

    /**
     * 제안 제목
     */
    @Column(name = "title", length = 100)
    private String title;

    /**
     * 제출 내용
     */
    @Column(name = "content", columnDefinition = "TEXT", nullable = false)
    private String content;

    /**
     * 카테고리
     */
    @Column(name = "category", length = 20)
    private String category;

    /**
     * 이미지 경로 (URL)
     */
    @Column(name = "image_path", length = 500)
    private String imagePath;

    /**
     * 첨부 파일 경로 (URL)
     */
    @Column(name = "file_url", length = 255)
    private String fileUrl;

    /**
     * 공감 개수
     */
    @Column(name = "empathy", nullable = false)
    private Integer empathy = 0;

    /**
     * 작성 시각
     * - 자동으로 현재 시각 설정
     */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Builder 패턴을 사용한 생성자
     */
    @Builder
    public ContestPost(Long contestId, Long parentPostId, String userId,
                       String title, String content, String category,
                       String imagePath, String fileUrl) {
        this.contestId = contestId;
        this.parentPostId = parentPostId;
        this.userId = userId;
        this.title = title;
        this.content = content;
        this.category = category;
        this.imagePath = imagePath;
        this.fileUrl = fileUrl;
        this.empathy = 0;
    }

    /**
     * 공감 수 증가
     */
    public void incrementEmpathy() {
        this.empathy++;
    }

    /**
     * 공감 수 감소
     */
    public void decrementEmpathy() {
        if (this.empathy > 0) {
            this.empathy--;
        }
    }
}
