package io.github.herbpot.miyobackend.common.controller;

import io.github.herbpot.miyobackend.common.dto.ImageUploadRequest;
import io.github.herbpot.miyobackend.common.dto.ImageUploadResponse;
import io.github.herbpot.miyobackend.common.service.NCPObjectStorageService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * ImageController
 * - ncp에 이미지 업로드 API
 * - Post와 Contest 도메인에서 공통으로 사용
 * - JWT 인증 필요
 */
@Slf4j
@RestController
@RequestMapping("/v0/images")
@RequiredArgsConstructor
@Tag(name = "Image Upload", description = "이미지 업로드 API")
public class ImageController {

    private final NCPObjectStorageService ncpObjectStorageService;

    /**
     * 비트맵 이미지 NCP 업로드
     *
     * @param request Base64로 인코딩된 비트맵 이미지 업로드 요청
     * @return 업로드된 이미지 URL
     */
    @PostMapping("/upload")
    @Operation(summary = "비트맵 이미지 업로드", description = "Base64로 인코딩된 비트맵 이미지를 NCP Object Storage에 업로드합니다.")
    public ResponseEntity<ImageUploadResponse> uploadImage(
            @Valid @RequestBody ImageUploadRequest request) {

        try {
            log.info("Bitmap image upload request received: contentType={}", request.getContentType());

            // Base64 이미지를 NCP Object Storage에 업로드
            String imageUrl = ncpObjectStorageService.uploadBase64Image(
                    request.getBase64Image(),
                    request.getContentType()
            );

            log.info("Bitmap image uploaded successfully: url={}", imageUrl);

            ImageUploadResponse response = ImageUploadResponse.builder()
                    .images(imageUrl)
                    .success(true)
                    .build();

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Failed to upload bitmap image", e);

            ImageUploadResponse response = ImageUploadResponse.builder()
                    .images(null)
                    .success(false)
                    .build();

            return ResponseEntity.badRequest().body(response);
        }
    }

}
