package io.github.herbpot.miyobackend.domain.challenge.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * 댓글 목록 응답 DTO
 * contests 필드에 댓글 목록을 담아 반환
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CommentsListResponse {

    /**
     * 댓글 목록 (대댓글 포함)
     */
    private List<CommentResponse> contests;

    /**
     * Factory method to create response from comment list
     */
    public static CommentsListResponse from(List<CommentResponse> comments) {
        return CommentsListResponse.builder()
                .contests(comments)
                .build();
    }
}
