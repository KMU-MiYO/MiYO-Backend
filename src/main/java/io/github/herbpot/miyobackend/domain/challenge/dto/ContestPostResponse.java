package io.github.herbpot.miyobackend.domain.challenge.dto;

import io.github.herbpot.miyobackend.domain.challenge.entity.ContestPost;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 공모전 제출물 응답 DTO
 * - ContestPost Entity로부터 생성
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ContestPostResponse {

    /**
     * 제출물 ID
     */
    private Long id;

    /**
     * 공모전 ID
     */
    private Long contestId;

    /**
     * 부모 게시글 ID (댓글인 경우)
     */
    private Long parentPostId;

    /**
     * 작성자 ID
     */
    private String userId;

    /**
     * 작성자 닉네임 (UserService에서 조회)
     */
    private String userNickname;

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
     * 첨부 파일 URL
     */
    private String fileUrl;

    /**
     * 공감 개수
     */
    private Integer empathy;

    /**
     * 작성 시각
     */
    private LocalDateTime createdAt;

    /**
     * 사용자의 공감 여부 (Optional)
     */
    private Boolean isEmpathized;

    /**
     * 댓글 목록 (Optional)
     */
    private List<CommentResponse> comments;

    /**
     * ContestPost Entity로부터 ContestPostResponse 생성
     */
    public static ContestPostResponse from(ContestPost contestPost) {
        return ContestPostResponse.builder()
                .id(contestPost.getId())
                .contestId(contestPost.getContestId())
                .parentPostId(contestPost.getParentPostId())
                .userId(contestPost.getUserId())
                .title(contestPost.getTitle())
                .content(contestPost.getContent())
                .category(contestPost.getCategory())
                .imagePath(contestPost.getImagePath())
                .fileUrl(contestPost.getFileUrl())
                .empathy(contestPost.getEmpathy())
                .createdAt(contestPost.getCreatedAt())
                .build();
    }

    /**
     * 사용자 닉네임을 포함한 ContestPostResponse 생성
     */
    public static ContestPostResponse fromWithNickname(ContestPost contestPost, String userNickname) {
        ContestPostResponse response = from(contestPost);
        response.userNickname = userNickname;
        return response;
    }

    /**
     * 공감 여부를 포함한 ContestPostResponse 생성
     */
    public static ContestPostResponse withEmpathy(ContestPost contestPost, String userNickname, Boolean isEmpathized) {
        ContestPostResponse response = fromWithNickname(contestPost, userNickname);
        response.isEmpathized = isEmpathized;
        return response;
    }

    /**
     * 댓글 목록을 포함한 ContestPostResponse 생성
     */
    public static ContestPostResponse withComments(ContestPost contestPost, String userNickname, List<CommentResponse> comments) {
        ContestPostResponse response = fromWithNickname(contestPost, userNickname);
        response.comments = comments;
        return response;
    }
}
