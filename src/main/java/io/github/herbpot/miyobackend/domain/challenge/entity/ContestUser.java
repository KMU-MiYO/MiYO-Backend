package io.github.herbpot.miyobackend.domain.challenge.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * ContestUser Entity
 * - 공모전 참가자 정보를 저장하는 엔티티
 * - ContestUser 테이블에 매핑
 * - 복합키 (contest_id, user_id) 사용
 */
@Entity
@Table(name = "ContestUser", indexes = {
    @Index(name = "idx_user_id", columnList = "user_id")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ContestUser {

    /**
     * 복합 Primary Key (contest_id, user_id)
     */
    @EmbeddedId
    private ContestUserId id;

    /**
     * 참여 일시
     * - 자동으로 현재 시각 설정
     */
    @CreationTimestamp
    @Column(name = "joined_at", nullable = false, updatable = false)
    private LocalDateTime joinedAt;

    /**
     * Builder 패턴을 사용한 생성자
     */
    @Builder
    public ContestUser(ContestUserId id) {
        this.id = id;
    }

    /**
     * 정적 팩토리 메서드
     * - contestId와 userId를 받아 ContestUser 생성
     */
    public static ContestUser of(Long contestId, String userId) {
        return ContestUser.builder()
                .id(new ContestUserId(contestId, userId))
                .build();
    }
}
