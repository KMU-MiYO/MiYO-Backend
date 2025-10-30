package io.github.herbpot.miyobackend.domain.challenge.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * ContestEmpathyEvent DTO
 * - Contest 공감 추가/취소 이벤트
 * - Redis Pub/Sub을 통해 Mission Subscriber로 전달
 * - ContestPost의 empathy 필드 카운팅 방식 사용
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ContestEmpathyEvent implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 이벤트 타입
     * - CREATE: 공감 추가
     * - DELETE: 공감 취소
     */
    public enum EventType {
        CREATE,   // 공감 추가
        DELETE    // 공감 취소
    }

    /**
     * 이벤트 타입
     */
    private EventType eventType;

    /**
     * 공감 대상 제출물/댓글 ID
     */
    private Long contestPostId;

    /**
     * 공감한 사용자 ID
     */
    private String userId;

    /**
     * 이전 공감 수
     */
    private Integer previousEmpathyCount;

    /**
     * 새로운 공감 수
     */
    private Integer newEmpathyCount;

    /**
     * 생성 시각
     */
    private LocalDateTime createdAt;

    /**
     * CREATE 이벤트 생성 (공감 추가)
     */
    public static ContestEmpathyEvent createEvent(Long contestPostId, String userId,
                                                   Integer previousCount, Integer newCount) {
        return ContestEmpathyEvent.builder()
                .eventType(EventType.CREATE)
                .contestPostId(contestPostId)
                .userId(userId)
                .previousEmpathyCount(previousCount)
                .newEmpathyCount(newCount)
                .createdAt(LocalDateTime.now())
                .build();
    }

    /**
     * DELETE 이벤트 생성 (공감 취소)
     */
    public static ContestEmpathyEvent deleteEvent(Long contestPostId, String userId,
                                                   Integer previousCount, Integer newCount) {
        return ContestEmpathyEvent.builder()
                .eventType(EventType.DELETE)
                .contestPostId(contestPostId)
                .userId(userId)
                .previousEmpathyCount(previousCount)
                .newEmpathyCount(newCount)
                .createdAt(LocalDateTime.now())
                .build();
    }
}
