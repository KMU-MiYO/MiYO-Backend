package io.github.herbpot.miyobackend.common.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * ImageGenerationResponse
 * - Gemini AI 이미지 생성 응답 DTO
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ImageGenerationResponse {

    /**
     * 생성된 이미지 URL 또는 Base64 데이터 리스트
     */
    private List<String> images;

    /**
     * 생성 성공 여부
     */
    private boolean success;

    /**
     * 에러 메시지 (실패 시)
     */
    private String errorMessage;

    /**
     * 사용된 프롬프트
     */
    private String prompt;

    /**
     * 성공 응답 생성
     */
    public static ImageGenerationResponse success(List<String> images, String prompt) {
        return ImageGenerationResponse.builder()
                .images(images)
                .success(true)
                .prompt(prompt)
                .build();
    }

    /**
     * 실패 응답 생성
     */
    public static ImageGenerationResponse failure(String errorMessage, String prompt) {
        return ImageGenerationResponse.builder()
                .success(false)
                .errorMessage(errorMessage)
                .prompt(prompt)
                .build();
    }
}
