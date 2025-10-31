package io.github.herbpot.miyobackend.domain.challenge.dto;

import io.github.herbpot.miyobackend.domain.challenge.entity.ContestPost;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * 댓글 응답 DTO
 * - 댓글 조회 시 필요한 필드만 포함
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CommentResponse {

    /**
     * 댓글 ID
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
     * 작성 시각
     */
    private LocalDateTime createdAt;

    /**
     * 공감 개수
     */
    private Integer empathyCount;

    /**
     * 댓글 내용
     */
    private String content;

    /**
     * 부모 게시글 ID
     */
    private Long parentPostId;

    /**
     * 대댓글 목록
     */
    @Builder.Default
    private List<CommentResponse> replies = new ArrayList<>();

    /**
     * ContestPost Entity로부터 CommentResponse 생성
     *
     * @param contestPost 댓글 엔티티
     * @param userNickname 사용자 닉네임
     * @return CommentResponse
     */
    public static CommentResponse from(ContestPost contestPost, String userNickname) {
        return CommentResponse.builder()
                .postId(contestPost.getId())
                .userId(contestPost.getUserId())
                .userNickname(userNickname)
                .createdAt(contestPost.getCreatedAt())
                .empathyCount(contestPost.getEmpathy())
                .content(contestPost.getContent())
                .parentPostId(contestPost.getParentPostId())
                .replies(new ArrayList<>())
                .build();
    }

    /**
     * ContestPost Entity로부터 CommentResponse 생성 (대댓글 포함)
     *
     * @param contestPost 댓글 엔티티
     * @param userNickname 사용자 닉네임
     * @param replies 대댓글 목록
     * @return CommentResponse
     */
    public static CommentResponse from(ContestPost contestPost, String userNickname, List<CommentResponse> replies) {
        return CommentResponse.builder()
                .postId(contestPost.getId())
                .userId(contestPost.getUserId())
                .userNickname(userNickname)
                .createdAt(contestPost.getCreatedAt())
                .empathyCount(contestPost.getEmpathy())
                .content(contestPost.getContent())
                .parentPostId(contestPost.getParentPostId())
                .replies(replies != null ? replies : new ArrayList<>())
                .build();
    }
}
