package io.github.herbpot.miyobackend.domain.community.entity.write;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * EmpathyData Entity (Write DB)
 * - 게시글 공감 데이터
 * - 한 사용자가 한 게시글에 하나의 공감만 가능
 * - userId + postId 복합키
 * - Write DB에 저장 후 Redis 이벤트를 통해 Read DB로 동기화
 */
@Entity
@Table(name = "empathy_data",
    uniqueConstraints = {
        @UniqueConstraint(columnNames = {"user_id", "post_id"})
    },
    indexes = {
        @Index(name = "idx_post_id", columnList = "post_id"),
        @Index(name = "idx_user_id", columnList = "user_id")
    }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class EmpathyData {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "empathy_id")
    private Long empathyId;

    /**
     * 사용자 ID
     * - User 테이블 참조 (ForeignKey)
     */
    @Column(name = "user_id", nullable = false)
    private String userId;

    /**
     * 게시글 ID
     * - Post 테이블 참조 (ForeignKey)
     */
    @Column(name = "post_id", nullable = false)
    private Long postId;

    /**
     * 공감 생성 일시
     */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Builder
    public EmpathyData(String userId, Long postId) {
        this.userId = userId;
        this.postId = postId;
    }
}
