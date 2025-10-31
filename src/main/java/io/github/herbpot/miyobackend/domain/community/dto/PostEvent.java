package io.github.herbpot.miyobackend.domain.community.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * PostEvent DTO
 * - Redis Pub/Sub을 통해 전송되는 이벤트 객체
 * - Write Model(Post)의 데이터를 Read Model로 전달
 * - Serializable 구현: Redis에서 직렬화/역직렬화 가능하도록
 * - eventType: CREATE, DELETE 등 이벤트 타입 구분
 * - Event 인터페이스 구현
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PostEvent implements Event, Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 이벤트 타입
     * - CREATE: 게시글 생성
     * - UPDATE: 게시글 수정 (논리 삭제 포함)
     * - DELETE: 게시글 삭제 (하드 삭제, 현재 미사용)
     */
    public enum EventType {
        CREATE, UPDATE, DELETE
    }

    /**
     * 이벤트 타입
     */
    private EventType eventType;

    /**
     * 게시글 ID
     */
    private Long postId;

    /**
     * 작성자 ID
     */
    private String userId;

    /**
     * 작성자 닉네임
     */
    private String userNickname;

    /**
     * 부모 게시글 ID
     */
    private Long parentPostId;

    /**
     * 이미지 경로
     */
    private String imagePath;

    /**
     * 위도
     */
    private Double latitude;

    /**
     * 경도
     */
    private Double longitude;

    /**
     * 카테고리
     */
    private String category;

    /**
     * 게시글 제목
     */
    private String title;

    /**
     * 게시글 내용
     */
    private String content;

    /**
     * 생성 일시
     */
    private LocalDateTime createdAt;

    /**
     * Event 인터페이스 구현
     * - 이벤트 타입 이름 반환
     */
    @Override
    @com.fasterxml.jackson.annotation.JsonIgnore
    public String getEventTypeName() {
        return "POST_EVENT";
    }
}
