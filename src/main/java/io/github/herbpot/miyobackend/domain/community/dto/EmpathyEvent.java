package io.github.herbpot.miyobackend.domain.community.dto;

import io.github.herbpot.miyobackend.domain.community.entity.write.EmpathyData;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * EmpathyEvent
 * - Redis Pub/Sub을 통해 전달되는 공감 이벤트
 * - Write DB에서 공감 생성/삭제 후 발행
 * - RedisEventSubscriber가 수신하여 Read DB 업데이트
 * - Event 인터페이스 구현
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmpathyEvent implements Event, Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 이벤트 타입
     */
    private EventType eventType;

    /**
     * 공감 ID
     */
    private Long empathyId;

    /**
     * 사용자 ID
     */
    private String userId;

    /**
     * 게시글 ID
     */
    private Long postId;

    /**
     * 공감 생성 일시
     */
    private LocalDateTime createdAt;

    /**
     * 이벤트 타입
     */
    public enum EventType {
        CREATE,  // 공감 추가
        DELETE   // 공감 삭제
    }

    /**
     * EmpathyData로부터 CREATE 이벤트 생성
     */
    public static EmpathyEvent createEvent(EmpathyData empathyData) {
        return EmpathyEvent.builder()
                .eventType(EventType.CREATE)
                .empathyId(empathyData.getEmpathyId())
                .userId(empathyData.getUserId())
                .postId(empathyData.getPostId())
                .createdAt(empathyData.getCreatedAt())
                .build();
    }

    /**
     * EmpathyData로부터 DELETE 이벤트 생성
     */
    public static EmpathyEvent deleteEvent(EmpathyData empathyData) {
        return EmpathyEvent.builder()
                .eventType(EventType.DELETE)
                .empathyId(empathyData.getEmpathyId())
                .userId(empathyData.getUserId())
                .postId(empathyData.getPostId())
                .createdAt(empathyData.getCreatedAt())
                .build();
    }

    /**
     * Event 인터페이스 구현
     * - 이벤트 타입 이름 반환
     */
    @Override
    public String getEventTypeName() {
        return "EMPATHY_EVENT";
    }
}
