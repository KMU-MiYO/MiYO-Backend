package io.github.herbpot.miyobackend.domain.challenge.dto;

import io.github.herbpot.miyobackend.domain.challenge.entity.ContestPost;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * ContestCommentEvent DTO
 * - Contest 댓글 생성/삭제 이벤트
 * - Redis Pub/Sub을 통해 Mission Subscriber로 전달
 * - parentPostId가 null이 아닌 경우만 해당 (댓글)
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ContestCommentEvent implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 이벤트 타입
     * - CREATE: 댓글 생성
     * - DELETE: 댓글 삭제
     */
    public enum EventType {
        CREATE,   // 댓글 생성
        DELETE    // 댓글 삭제
    }

    /**
     * 이벤트 타입
     */
    private EventType eventType;

    /**
     * 댓글 ID (ContestPost.id)
     */
    private Long contestPostId;

    /**
     * 공모전 ID
     */
    private Long contestId;

    /**
     * 부모 제출물 ID (필수)
     */
    private Long parentPostId;

    /**
     * 작성자 ID
     */
    private String userId;

    /**
     * 댓글 내용
     */
    private String content;

    /**
     * 제목 (부모로부터 상속)
     */
    private String title;

    /**
     * 카테고리 (부모로부터 상속)
     */
    private String category;

    /**
     * 생성 시각
     */
    private LocalDateTime createdAt;

    /**
     * ContestPost Entity로부터 CREATE 이벤트 생성
     * - 댓글은 parentPostId가 필수
     */
    public static ContestCommentEvent createEvent(ContestPost comment) {
        return ContestCommentEvent.builder()
                .eventType(EventType.CREATE)
                .contestPostId(comment.getId())
                .contestId(comment.getContestId())
                .parentPostId(comment.getParentPostId())  // 필수! 부모 ID
                .userId(comment.getUserId())
                .content(comment.getContent())
                .title(comment.getTitle())  // 부모로부터 상속
                .category(comment.getCategory())  // 부모로부터 상속
                .createdAt(comment.getCreatedAt())
                .build();
    }

    /**
     * DELETE 이벤트 생성
     * - 삭제 시에는 contestPostId, parentPostId, userId만 필요
     */
    public static ContestCommentEvent deleteEvent(Long contestPostId, Long parentPostId, String userId) {
        return ContestCommentEvent.builder()
                .eventType(EventType.DELETE)
                .contestPostId(contestPostId)
                .parentPostId(parentPostId)
                .userId(userId)
                .build();
    }
}
