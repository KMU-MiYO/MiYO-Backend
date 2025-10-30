package io.github.herbpot.miyobackend.domain.community.dto;

import io.github.herbpot.miyobackend.domain.community.entity.write.Post;
import io.github.herbpot.miyobackend.domain.community.entity.PostCategory;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 게시글 생성 응답 DTO
 * - POST /v0/posts API의 Response Body
 * - Write Model(Post)로부터 생성
 */
@Schema(description = "게시글 생성 응답")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PostResponse {

    /**
     * 게시글 ID
     */
    @Schema(description = "게시글 ID", example = "1")
    private Long postId;

    /**
     * 작성자 ID
     */
    @Schema(description = "작성자 ID", example = "user123")
    private String userId;

    /**
     * 작성자 닉네임
     */
    @Schema(description = "작성자 닉네임", example = "홍길동")
    private String userNickname;

    /**
     * 부모 게시글 ID
     */
    @Schema(description = "부모 게시글 ID (댓글인 경우)", example = "null")
    private Long parentPostId;

    /**
     * 이미지 경로
     */
    @Schema(description = "이미지 경로 (URL)", example = "https://example.com/images/post.jpg")
    private String imagePath;

    /**
     * 위도
     */
    @Schema(description = "위도", example = "37.5665")
    private Double latitude;

    /**
     * 경도
     */
    @Schema(description = "경도", example = "126.9780")
    private Double longitude;

    /**
     * 카테고리
     */
    @Schema(description = "게시글 카테고리", example = "NATURE")
    private PostCategory category;

    /**
     * 게시글 제목
     */
    @Schema(description = "게시글 제목", example = "서울숲 단풍이 정말 아름다워요")
    private String title;

    /**
     * 게시글 내용
     */
    @Schema(description = "게시글 내용", example = "서울숲에 단풍이 물들었어요. 가을 산책하기 정말 좋은 날씨입니다!")
    private String content;

    /**
     * 생성 일시
     */
    @Schema(description = "생성 일시", example = "2025-10-31T10:30:00")
    private LocalDateTime createdAt;

    /**
     * Post Entity로부터 PostResponse 생성
     */
    public static PostResponse from(Post post) {
        return PostResponse.builder()
                .postId(post.getPostId())
                .userId(post.getUserId())
                .parentPostId(post.getParentPostId())
                .imagePath(post.getImagePath())
                .latitude(post.getLatitude())
                .longitude(post.getLongitude())
                .category(post.getCategory())
                .title(post.getTitle())
                .content(post.getContent())
                .createdAt(post.getCreatedAt())
                .build();
    }
}
