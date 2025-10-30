package io.github.herbpot.miyobackend.domain.community.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 사용자 활동 조회 응답 DTO
 * - 사용자의 게시글, 댓글, 공감 목록 조회 시 사용
 * - 총 개수와 페이징된 리스트를 함께 반환
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class UserActivityResponse {

    /**
     * 총 개수
     */
    private long totalCount;

    /**
     * 게시글 목록 (페이징)
     */
    private PageResponse<PostListResponse> posts;

    /**
     * 사용자 게시글 응답 생성
     */
    public static UserActivityResponse ofPosts(long totalCount, PageResponse<PostListResponse> posts) {
        return new UserActivityResponse(totalCount, posts);
    }

    /**
     * 사용자 댓글 응답 생성
     */
    public static UserActivityResponse ofComments(long totalCount, PageResponse<PostListResponse> comments) {
        return new UserActivityResponse(totalCount, comments);
    }

    /**
     * 사용자 공감 응답 생성
     */
    public static UserActivityResponse ofEmpathy(long totalCount, PageResponse<PostListResponse> empathy) {
        return new UserActivityResponse(totalCount, empathy);
    }
}
