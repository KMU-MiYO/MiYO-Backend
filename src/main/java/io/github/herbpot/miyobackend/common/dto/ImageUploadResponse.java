package io.github.herbpot.miyobackend.common.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * ImageUploadResponse
 * - 비트맵 이미지 업로드 응답 DTO
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ImageUploadResponse {

    /**
     * 업로드된 이미지 URL
     */
    private String imageUrl;

    /**
     * 업로드 성공 여부
     */
    private boolean success;

    /**
     * 에러 메시지 (실패 시)
     */
    private String errorMessage;

    /**
     * 성공 응답 생성
     */
    public static ImageUploadResponse success(String imageUrl) {
        return ImageUploadResponse.builder()
                .imageUrl(imageUrl)
                .success(true)
                .build();
    }

    /**
     * 실패 응답 생성
     */
    public static ImageUploadResponse failure(String errorMessage) {
        return ImageUploadResponse.builder()
                .success(false)
                .errorMessage(errorMessage)
                .build();
    }
}
