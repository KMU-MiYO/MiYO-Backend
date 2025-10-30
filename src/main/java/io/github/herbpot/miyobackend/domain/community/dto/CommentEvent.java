package io.github.herbpot.miyobackend.domain.community.dto;

import io.github.herbpot.miyobackend.domain.community.entity.write.Post;
import io.github.herbpot.miyobackend.domain.community.entity.PostCategory;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * CommentEvent DTO
 * - Redis Pub/Sub을 통해 전송되는 댓글 이벤트 객체
 * - Write Model(Post - 댓글)의 데이터를 Read Model로 전달
 * - Serializable 구현: Redis에서 직렬화/역직렬화 가능하도록
 * - eventType: CREATE, DELETE 등 이벤트 타입 구분
 * - Event 인터페이스 구현
 * - 댓글은 Post 엔티티를 재사용하지만 명확한 이벤트 타입으로 분리
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CommentEvent implements Event, Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 이벤트 타입
     * - CREATE: 댓글 생성
     * - DELETE: 댓글 삭제
     */
    public enum EventType {
        CREATE, DELETE
    }

    /**
     * 이벤트 타입
     */
    private EventType eventType;

    /**
     * 댓글 ID (Post 엔티티의 postId)
     */
    private Long commentId;

    /**
     * 부모 게시글 ID (필수)
     */
    private Long parentPostId;

    /**
     * 작성자 ID
     */
    private String userId;

    /**
     * 작성자 닉네임
     */
    private String userNickname;

    /**
     * 댓글 내용
     */
    private String content;

    /**
     * 위도 (부모 게시글로부터 상속)
     */
    private Double latitude;

    /**
     * 경도 (부모 게시글로부터 상속)
     */
    private Double longitude;

    /**
     * 카테고리 (부모 게시글로부터 상속)
     */
    private PostCategory category;

    /**
     * 제목 (부모 게시글로부터 상속)
     */
    private String title;

    /**
     * 생성 일시
     */
    private LocalDateTime createdAt;

    /**
     * Post Entity로부터 CREATE 이벤트 생성
     * - 댓글은 Post 엔티티를 재사용하지만 parentPostId가 필수
     */
    public static CommentEvent createEvent(Post comment, String userNickname) {
        return CommentEvent.builder()
                .eventType(EventType.CREATE)
                .commentId(comment.getPostId())
                .parentPostId(comment.getParentPostId())
                .userId(comment.getUserId())
                .userNickname(userNickname)
                .content(comment.getContent())
                .latitude(comment.getLatitude())
                .longitude(comment.getLongitude())
                .category(comment.getCategory())
                .title(comment.getTitle())
                .createdAt(comment.getCreatedAt())
                .build();
    }

    /**
     * DELETE 이벤트 생성
     * - 삭제 시에는 commentId와 parentPostId만 필요
     */
    public static CommentEvent deleteEvent(Long commentId, Long parentPostId) {
        return CommentEvent.builder()
                .eventType(EventType.DELETE)
                .commentId(commentId)
                .parentPostId(parentPostId)
                .build();
    }

    /**
     * Event 인터페이스 구현
     * - 이벤트 타입 이름 반환
     */
    @Override
    @com.fasterxml.jackson.annotation.JsonIgnore
    public String getEventTypeName() {
        return "COMMENT_EVENT";
    }
}
