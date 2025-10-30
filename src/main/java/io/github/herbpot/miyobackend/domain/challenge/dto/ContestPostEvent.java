package io.github.herbpot.miyobackend.domain.challenge.dto;

import io.github.herbpot.miyobackend.domain.challenge.entity.ContestPost;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * ContestPostEvent DTO
 * - Contest 제출물 생성/삭제 이벤트
 * - Redis Pub/Sub을 통해 Mission Subscriber로 전달
 * - parentPostId가 null인 경우만 해당 (원본 제출물)
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ContestPostEvent implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 이벤트 타입
     * - CREATE: 제출물 생성
     * - DELETE: 제출물 삭제
     */
    public enum EventType {
        CREATE,   // 제출물 생성
        DELETE    // 제출물 삭제
    }

    /**
     * 이벤트 타입
     */
    private EventType eventType;

    /**
     * 제출물 ID (ContestPost.id)
     */
    private Long contestPostId;

    /**
     * 공모전 ID
     */
    private Long contestId;

    /**
     * 작성자 ID
     */
    private String userId;

    /**
     * 부모 제출물 ID (원본 제출물은 null)
     */
    private Long parentPostId;

    /**
     * 제안 제목
     */
    private String title;

    /**
     * 제출 내용
     */
    private String content;

    /**
     * 카테고리
     */
    private String category;

    /**
     * 이미지 경로
     */
    private String imagePath;

    /**
     * 첨부 파일 경로
     */
    private String fileUrl;

    /**
     * 생성 시각
     */
    private LocalDateTime createdAt;

    /**
     * ContestPost Entity로부터 CREATE 이벤트 생성
     */
    public static ContestPostEvent createEvent(ContestPost contestPost) {
        return ContestPostEvent.builder()
                .eventType(EventType.CREATE)
                .contestPostId(contestPost.getId())
                .contestId(contestPost.getContestId())
                .userId(contestPost.getUserId())
                .parentPostId(null)  // 원본 제출물은 항상 null
                .title(contestPost.getTitle())
                .content(contestPost.getContent())
                .category(contestPost.getCategory())
                .imagePath(contestPost.getImagePath())
                .fileUrl(contestPost.getFileUrl())
                .createdAt(contestPost.getCreatedAt())
                .build();
    }

    /**
     * DELETE 이벤트 생성
     * - 삭제 시에는 contestPostId, contestId, userId만 필요
     */
    public static ContestPostEvent deleteEvent(Long contestPostId, Long contestId, String userId) {
        return ContestPostEvent.builder()
                .eventType(EventType.DELETE)
                .contestPostId(contestPostId)
                .contestId(contestId)
                .userId(userId)
                .build();
    }
}
