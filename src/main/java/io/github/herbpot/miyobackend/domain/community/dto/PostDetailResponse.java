package io.github.herbpot.miyobackend.domain.community.dto;

import io.github.herbpot.miyobackend.domain.community.entity.PostCategory;
import io.github.herbpot.miyobackend.domain.community.entity.read.PostReadModel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 게시글 상세 조회 응답 DTO
 * - GET /v0/posts/id API의 Response Body
 * - Read Model(PostReadModel)로부터 생성
 * - content를 포함한 모든 정보 제공
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PostDetailResponse {

    /**
     * 게시글 ID
     */
    private Long postId;

    /**
     * 작성자 닉네임
     */
    private String nickname;

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
     * 게시글 전체 내용
     */
    private String content;

    /**
     * 생성 일시
     */
    private LocalDateTime createdAt;

    /**
     * 공감 수
     */
    private Long empathyCount;

    /**
     * 현재 사용자의 공감 여부
     */
    private Boolean isEmpathized;

    /**
     * 댓글 목록 (트리 구조)
     * - 해당 게시글의 댓글들
     * - 최신순으로 정렬
     * - 대댓글 포함 (최대 2단계: 댓글 -> 대댓글)
     * - 제외 항목: 위치 정보, 제목, 이미지, 카테고리
     */
    private List<CommentResponse> comments;

    /**
     * PostReadModel로부터 PostDetailResponse 생성
     * - 모든 필드 포함
     * - nickname은 별도로 User 테이블에서 조회하여 전달
     * - comments는 별도로 조회하여 트리 구조로 전달
     */
    public static PostDetailResponse from(PostReadModel readModel, String nickname, Long empathyCount, Boolean isEmpathized, List<CommentResponse> comments) {
        return PostDetailResponse.builder()
                .postId(readModel.getPostId())
                .nickname(nickname)
                .parentPostId(readModel.getParentPostId())
                .imagePath(readModel.getImagePath())
                .latitude(readModel.getLatitude())
                .longitude(readModel.getLongitude())
                .category(readModel.getCategory())
                .title(readModel.getTitle())
                .content(readModel.getContent())
                .createdAt(readModel.getCreatedAt())
                .empathyCount(empathyCount != null ? empathyCount : 0L)
                .isEmpathized(isEmpathized != null ? isEmpathized : false)
                .comments(comments != null ? comments : List.of())
                .build();
    }
}
