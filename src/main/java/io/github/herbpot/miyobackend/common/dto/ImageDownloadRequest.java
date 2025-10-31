package io.github.herbpot.miyobackend.common.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * ImageDownloadRequest
 * - NCP Object Storage 이미지 다운로드 요청 DTO
 * - CORS 우회를 위한 프록시 API용
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ImageDownloadRequest {

    /**
     * 이미지 경로
     * - 전체 URL 또는 Object Storage Key
     * - 예: "https://bucket.kr.object.ncloudstorage.com/images/abc.png"
     * - 예: "images/abc.png"
     */
    @NotBlank(message = "이미지 경로는 필수입니다.")
    private String imagePath;
}
