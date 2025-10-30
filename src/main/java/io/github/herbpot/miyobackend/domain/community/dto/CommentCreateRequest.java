package io.github.herbpot.miyobackend.domain.community.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 댓글 작성 요청 DTO
 * - POST /v0/comments API의 Request Body
 * - 댓글은 이미지를 받지 않음
 * - 위치 정보, 카테고리, 제목은 부모 게시글로부터 상속받음 (클라이언트에서 전송 불필요)
 * - userId는 JWT에서 추출하여 설정됨 (클라이언트에서 전송 불필요)
 */
@Schema(description = "댓글 작성 요청")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CommentCreateRequest {

    /**
     * 부모 게시글/댓글 ID (필수)
     * - 댓글을 달 게시글 또는 댓글의 ID
     */
    @Schema(description = "부모 게시글/댓글 ID", example = "1", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotNull(message = "부모 게시글 ID는 필수입니다.")
    private Long parentPostId;

    /**
     * 댓글 내용
     * - 1자 이상, 5000자 이하
     */
    @Schema(description = "댓글 내용 (1~5000자)", example = "저도 가봤는데 정말 좋았어요!", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "댓글 내용은 필수입니다.")
    @Size(min = 1, max = 5000, message = "댓글 내용은 1자 이상 5000자 이하이어야 합니다.")
    private String content;
}
