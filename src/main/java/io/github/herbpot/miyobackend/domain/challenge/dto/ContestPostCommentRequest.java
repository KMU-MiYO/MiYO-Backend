package io.github.herbpot.miyobackend.domain.challenge.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 공모전 제출물 댓글 작성 요청 DTO
 * - POST /v0/contests/posts/{postId}/comments API의 Request Body
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ContestPostCommentRequest {

    /**
     * 댓글 내용
     */
    @NotBlank(message = "댓글 내용은 필수입니다.")
    @Size(min = 1, max = 5000, message = "댓글 내용은 1자 이상 5000자 이하이어야 합니다.")
    private String content;
}
