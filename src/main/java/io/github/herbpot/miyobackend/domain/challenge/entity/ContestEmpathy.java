package io.github.herbpot.miyobackend.domain.challenge.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * ContestEmpathy Entity
 * - 공모전 제출물에 대한 공감 정보를 저장하는 엔티티
 * - user_id와 post_id의 조합으로 중복 공감 방지
 */
@Entity
@Table(name = "ContestEmpathy",
    uniqueConstraints = {
        @UniqueConstraint(name = "uk_user_post", columnNames = {"user_id", "post_id"})
    },
    indexes = {
        @Index(name = "idx_post_id", columnList = "post_id"),
        @Index(name = "idx_user_id", columnList = "user_id")
    }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ContestEmpathy {

    /**
     * 공감 ID (Primary Key)
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    /**
     * 공감한 사용자 ID
     */
    @Column(name = "user_id", nullable = false, length = 255)
    private String userId;

    /**
     * 공감 대상 게시물 ID
     */
    @Column(name = "post_id", nullable = false)
    private Long postId;

    /**
     * 공감 생성 시각
     */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Builder 패턴을 사용한 생성자
     */
    @Builder
    public ContestEmpathy(String userId, Long postId) {
        this.userId = userId;
        this.postId = postId;
    }
}
