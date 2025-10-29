package io.github.herbpot.miyobackend.common.controller;

import io.github.herbpot.miyobackend.common.dto.ImageEditRequest;
import io.github.herbpot.miyobackend.common.dto.ImageGenerationRequest;
import io.github.herbpot.miyobackend.common.dto.ImageGenerationResponse;
import io.github.herbpot.miyobackend.common.service.GeminiImageService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * ImageController
 * - AI 이미지 생성 API
 * - Post와 Contest 도메인에서 공통으로 사용
 * - JWT 인증 필요
 */
@Slf4j
@RestController
@RequestMapping("/v0/images")
@RequiredArgsConstructor
public class ImageController {

    private final GeminiImageService geminiImageService;

    /**
     * AI 이미지 생성 및 NCP 업로드
     *
     * @param request 이미지 생성 요청 (프롬프트 포함)
     * @param authentication Spring Security Authentication
     * @return 생성된 이미지 NCP URL (200 OK)
     */
    @PostMapping("/generate")
    public ResponseEntity<ImageGenerationResponse> generateImage(
            @Valid @RequestBody ImageGenerationRequest request,
            Authentication authentication) {

        String userId = (String) authentication.getPrincipal();
        log.info("POST /v0/images/generate - Generating and uploading image: userId={}, prompt='{}'",
                userId, request.getPrompt());

        // 이미지 생성 후 NCP에 업로드하여 URL 반환
        ImageGenerationResponse response = geminiImageService.generateAndUploadImage(request);

        if (response.isSuccess()) {
            log.info("Image generation and upload successful: userId={}, imageCount={}, urls={}",
                    userId, response.getImages().size(), response.getImages());
            return ResponseEntity.ok(response);
        } else {
            log.error("Image generation or upload failed: userId={}, error={}",
                    userId, response.getErrorMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * 이미지 기반 AI 이미지 생성 및 NCP 업로드
     * - 기존 이미지 URL과 프롬프트를 받아 새로운 이미지 생성
     *
     * @param request 이미지 편집 요청 (imageUrl + prompt)
     * @param authentication Spring Security Authentication
     * @return 생성된 이미지 NCP URL (200 OK)
     */
    @PostMapping("/generate-from-image")
    public ResponseEntity<ImageGenerationResponse> generateImageFromImage(
            @Valid @RequestBody ImageEditRequest request,
            Authentication authentication) {

        String userId = (String) authentication.getPrincipal();
        log.info("POST /v0/images/generate-from-image - Generating image from image: userId={}, imageUrl={}, prompt='{}'",
                userId, request.getImageUrl(), request.getPrompt());

        // 이미지 기반 이미지 생성 후 NCP에 업로드하여 URL 반환
        ImageGenerationResponse response = geminiImageService.generateAndUploadImageFromImage(request);

        if (response.isSuccess()) {
            log.info("Image generation from image and upload successful: userId={}, imageCount={}, urls={}",
                    userId, response.getImages().size(), response.getImages());
            return ResponseEntity.ok(response);
        } else {
            log.error("Image generation from image or upload failed: userId={}, error={}",
                    userId, response.getErrorMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * 헬스체크 엔드포인트
     *
     * @return 서비스 상태 (200 OK)
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Image generation service is running");
    }
}
