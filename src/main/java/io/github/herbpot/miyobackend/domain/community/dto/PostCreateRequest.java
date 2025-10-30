package io.github.herbpot.miyobackend.domain.community.dto;

import io.github.herbpot.miyobackend.domain.community.entity.PostCategory;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 게시글 작성 요청 DTO
 * - POST /v0/posts API의 Request Body
 * - Validation 어노테이션을 통한 입력값 검증
 * - userId는 JWT에서 추출하여 설정됨 (클라이언트에서 전송 불필요)
 */
@Schema(description = "게시글 작성 요청")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class PostCreateRequest {

    /**
     * 이미지 경로 (URL)
     * - 선택 사항
     */
    @Schema(description = "이미지 경로 (URL)", example = "https://example.com/images/post.jpg")
    private String imagePath;

    /**
     * 위도 (latitude)
     * - -90 ~ 90 범위
     */
    @Schema(description = "위도 (-90 ~ 90 범위)", example = "37.5665", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotNull(message = "위도는 필수입니다.")
    @DecimalMin(value = "-90.0", message = "위도는 -90 이상이어야 합니다.")
    @DecimalMax(value = "90.0", message = "위도는 90 이하이어야 합니다.")
    private Double latitude;

    /**
     * 경도 (longitude)
     * - -180 ~ 180 범위
     */
    @Schema(description = "경도 (-180 ~ 180 범위)", example = "126.9780", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotNull(message = "경도는 필수입니다.")
    @DecimalMin(value = "-180.0", message = "경도는 -180 이상이어야 합니다.")
    @DecimalMax(value = "180.0", message = "경도는 180 이하이어야 합니다.")
    private Double longitude;

    /**
     * 게시글 카테고리
     */
    @Schema(description = "게시글 카테고리 (NATURE, CULTURE, TRAFFIC, RESIDENCE, COMMERCIAL, NIGHT, ENVIRONMENT)",
            example = "NATURE",
            requiredMode = Schema.RequiredMode.REQUIRED)
    @NotNull(message = "카테고리는 필수입니다.")
    private PostCategory category;

    /**
     * 게시글 제목
     * - 1자 이상, 100자 이하
     */
    @Schema(description = "게시글 제목 (1~100자)", example = "서울숲 단풍이 정말 아름다워요", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "게시글 제목은 필수입니다.")
    @Size(min = 1, max = 100, message = "게시글 제목은 1자 이상 100자 이하이어야 합니다.")
    private String title;

    /**
     * 게시글 내용
     * - 1자 이상, 5000자 이하
     */
    @Schema(description = "게시글 내용 (1~5000자)", example = "서울숲에 단풍이 물들었어요. 가을 산책하기 정말 좋은 날씨입니다!", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "게시글 내용은 필수입니다.")
    @Size(min = 1, max = 5000, message = "게시글 내용은 1자 이상 5000자 이하이어야 합니다.")
    private String content;
}
