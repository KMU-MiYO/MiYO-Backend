package io.github.herbpot.miyobackend.common.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * ImageGenerationRequest
 * - Gemini AI 이미지 생성 요청 DTO
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ImageGenerationRequest {

    @NotBlank(message = "프롬프트는 필수입니다.")
    @Size(max = 1000, message = "프롬프트는 1000자를 초과할 수 없습니다.")
    private String prompt;

    /**
     * 이미지 생성 개수 (기본값: 1)
     */
    private Integer numberOfImages = 1;

    /**
     * 이미지 크기 (기본값: 1024x1024)
     * 가능한 값: 256x256, 512x512, 1024x1024
     */
    private String size = "1024x1024";
}
