package io.github.herbpot.miyobackend.domain.community.dto;

import io.github.herbpot.miyobackend.domain.community.entity.PostCategory;
import io.github.herbpot.miyobackend.domain.community.entity.read.PostReadModel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 게시글 목록 조회 응답 DTO
 * - GET /v0/posts/cord API의 content 항목
 * - Read Model(PostReadModel)로부터 생성
 * - 목록 조회 시 필요한 최소한의 정보만 포함
 * - postId, userEmail, category, title만 반환 (댓글 제외)
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PostListResponse {

    /**
     * 게시글 ID
     */
    private Long postId;

    /**
     * 작성자 닉네임
     */
    private String nickname;

    /**
     * 카테고리
     */
    private PostCategory category;

    /**
     * 게시글 제목
     */
    private String title;

    /**
     * 이미지 경로 (URL)
     */
    private String imagePath;

    /**
     * 공감 수
     */
    private Long empathyCount;

    /**
     * 생성 일시
     */
    private LocalDateTime createdAt;

    /**
     * 위도
     */
    private Double latitude;

    /**
     * 경도
     */
    private Double longitude;

    /**
     * 게시글/댓글 내용
     */
    private String content;

    /**
     * PostReadModel로부터 PostListResponse 생성
     * - parentPostId가 null인 게시글만 조회 (댓글 제외)
     * - postId, nickname, category, title, imagePath, empathyCount, createdAt, latitude, longitude, content 포함
     * - nickname은 별도로 User 테이블에서 조회하여 전달
     */
    public static PostListResponse from(PostReadModel readModel, String nickname, Long empathyCount) {
        return PostListResponse.builder()
                .postId(readModel.getPostId())
                .nickname(nickname)
                .category(readModel.getCategory())
                .title(readModel.getTitle())
                .imagePath(readModel.getImagePath())
                .empathyCount(empathyCount != null ? empathyCount : 0L)
                .createdAt(readModel.getCreatedAt())
                .latitude(readModel.getLatitude())
                .longitude(readModel.getLongitude())
                .content(readModel.getContent())
                .build();
    }
}
