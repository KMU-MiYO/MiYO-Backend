package io.github.herbpot.miyobackend.common.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * ImageUploadRequest
 * - 비트맵 이미지 업로드 요청 DTO
 * - Base64로 인코딩된 이미지 데이터를 받습니다
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ImageUploadRequest {

    @NotBlank(message = "이미지 데이터는 필수입니다.")
    private String base64Image;

    /**
     * 이미지 MIME 타입 (기본값: image/png)
     * 가능한 값: image/png, image/jpeg, image/jpg, image/gif, image/webp
     */
    private String contentType = "image/png";
}
