package io.github.herbpot.miyobackend.common.controller;

import io.github.herbpot.miyobackend.common.dto.ImageGenerationRequest;
import io.github.herbpot.miyobackend.common.dto.ImageGenerationResponse;
import io.github.herbpot.miyobackend.common.service.GeminiImageService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * ImageGenerationController
 * - Gemini AI 이미지 생성 API
 * - 생성된 이미지를 NCP Object Storage에 업로드
 */
@Slf4j
@RestController
@RequestMapping("/api/images")
@RequiredArgsConstructor
@Tag(name = "Image Generation", description = "AI 이미지 생성 API")
public class ImageGenerationController {

    private final GeminiImageService geminiImageService;

    /**
     * 이미지 생성 및 NCP 업로드
     *
     * @param request 이미지 생성 요청
     * @return 생성된 이미지 URL 목록
     */
    @PostMapping("/generate")
    @Operation(summary = "AI 이미지 생성 및 업로드", description = "Gemini AI로 이미지를 생성하고 NCP Object Storage에 업로드합니다.")
    public ResponseEntity<ImageGenerationResponse> generateAndUploadImage(
            @RequestBody ImageGenerationRequest request) {

        log.info("Image generation request received: prompt={}", request.getPrompt());

        ImageGenerationResponse response = geminiImageService.generateAndUploadImage(request);

        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    /**
     * 이미지 생성만 (Base64 반환, 업로드 안 함)
     *
     * @param request 이미지 생성 요청
     * @return Base64 인코딩된 이미지 데이터
     */
    @PostMapping("/generate-base64")
    @Operation(summary = "AI 이미지 생성 (Base64)", description = "Gemini AI로 이미지를 생성하고 Base64로 반환합니다.")
    public ResponseEntity<ImageGenerationResponse> generateImageBase64(
            @RequestBody ImageGenerationRequest request) {

        log.info("Image generation (Base64) request received: prompt={}", request.getPrompt());

        ImageGenerationResponse response = geminiImageService.generateImage(request);

        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }
}
