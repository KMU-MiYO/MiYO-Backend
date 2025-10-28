package io.github.herbpot.miyobackend.domain.challenge.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 공모전 제출물 작성 요청 DTO
 * - POST /v0/contests/{contestId}/posts API의 Request Body
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ContestPostCreateRequest {

    /**
     * 제안 제목
     */
    @NotBlank(message = "제목은 필수입니다.")
    @Size(min = 1, max = 100, message = "제목은 1자 이상 100자 이하이어야 합니다.")
    private String title;

    /**
     * 제출 내용
     */
    @NotBlank(message = "내용은 필수입니다.")
    @Size(min = 1, max = 5000, message = "내용은 1자 이상 5000자 이하이어야 합니다.")
    private String content;

    /**
     * 카테고리 (선택)
     */
    @Size(max = 20, message = "카테고리는 20자 이하이어야 합니다.")
    private String category;

    /**
     * 이미지 경로 (선택)
     * - 이미 업로드된 이미지 URL (AI 생성 이미지 등)
     * - base64Image와 동시에 존재할 경우 imagePath 우선
     */
    @Size(max = 500, message = "이미지 경로는 500자 이하이어야 합니다.")
    private String imagePath;

    /**
     * Base64 인코딩된 이미지 데이터 (선택)
     * - 사용자가 직접 업로드한 이미지
     * - imagePath가 없을 경우 NCP Object Storage에 업로드
     */
    private String base64Image;

    /**
     * 첨부 파일 URL (선택)
     */
    @Size(max = 255, message = "첨부 파일 URL은 255자 이하이어야 합니다.")
    private String fileUrl;
}
