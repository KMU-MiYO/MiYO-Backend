package io.github.herbpot.miyobackend.domain.community.dto;

import io.github.herbpot.miyobackend.domain.community.entity.Post;
import io.github.herbpot.miyobackend.domain.community.entity.PostCategory;
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
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PostResponse {

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
    private PostCategory category;

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
