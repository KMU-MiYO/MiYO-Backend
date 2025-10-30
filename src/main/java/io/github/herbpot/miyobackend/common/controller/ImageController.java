package io.github.herbpot.miyobackend.common.controller;

import io.github.herbpot.miyobackend.common.dto.*;
import io.github.herbpot.miyobackend.common.service.GeminiImageService;
import io.github.herbpot.miyobackend.common.service.NCPObjectStorageService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "이미지 API", description = "AI 이미지 생성 및 업로드 API")
@Slf4j
@RestController
@RequestMapping("/v0/images")
@RequiredArgsConstructor
public class ImageController {

    private final GeminiImageService geminiImageService;

    private final NCPObjectStorageService ncpObjectStorageService;

    /**
     * 비트맵 이미지 NCP 업로드
     *
     * @param request Base64로 인코딩된 비트맵 이미지 업로드 요청
     * @return 업로드된 이미지 URL
     */
    @Operation(
            summary = "비트맵 이미지 업로드",
            description = """
                    Base64로 인코딩된 비트맵 이미지를 NCP Object Storage에 업로드합니다.

                    지원 형식: PNG, JPEG, GIF, BMP
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "업로드 성공",
                    content = @Content(schema = @Schema(implementation = ImageUploadResponse.class))
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 이미지 형식 또는 요청 데이터"),
            @ApiResponse(responseCode = "500", description = "서버 오류 또는 업로드 실패")
    })
    @PostMapping("/upload")
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

            return ResponseEntity.ok(ImageUploadResponse.success(imageUrl));

        } catch (Exception e) {
            log.error("Failed to upload bitmap image", e);

            return ResponseEntity.badRequest()
                    .body(ImageUploadResponse.failure("이미지 업로드에 실패했습니다: " + e.getMessage()));
        }
    }

    /**
     * AI 이미지 생성 및 NCP 업로드
     *
     * @param request 이미지 생성 요청 (프롬프트 포함)
     * @param authentication Spring Security Authentication
     * @return 생성된 이미지 NCP URL (200 OK)
     */
    @Operation(
            summary = "AI 이미지 생성",
            description = """
                    텍스트 프롬프트를 기반으로 AI 이미지를 생성하고 NCP Object Storage에 업로드합니다.

                    - Gemini AI 모델을 사용하여 이미지 생성
                    - 생성된 이미지는 자동으로 NCP에 업로드되어 URL 반환
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "이미지 생성 및 업로드 성공",
                    content = @Content(schema = @Schema(implementation = ImageGenerationResponse.class))
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 프롬프트 또는 요청 데이터"),
            @ApiResponse(responseCode = "401", description = "인증 실패"),
            @ApiResponse(responseCode = "500", description = "AI 이미지 생성 실패 또는 업로드 오류")
    })
    @PostMapping("/generate")
    public ResponseEntity<ImageGenerationResponse> generateImage(
            @Valid @RequestBody ImageGenerationRequest request,
            @Parameter(hidden = true) Authentication authentication) {

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
    @Operation(
            summary = "이미지 기반 AI 이미지 생성",
            description = """
                    기존 이미지 URL과 텍스트 프롬프트를 기반으로 새로운 AI 이미지를 생성합니다.

                    - 이미지-투-이미지 변환 기능
                    - 기존 이미지를 참고하여 새로운 스타일의 이미지 생성
                    - Gemini AI 모델 사용
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "이미지 생성 및 업로드 성공",
                    content = @Content(schema = @Schema(implementation = ImageGenerationResponse.class))
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 이미지 URL 또는 프롬프트"),
            @ApiResponse(responseCode = "401", description = "인증 실패"),
            @ApiResponse(responseCode = "500", description = "AI 이미지 생성 실패 또는 업로드 오류")
    })
    @PostMapping("/generate-from-image")
    public ResponseEntity<ImageGenerationResponse> generateImageFromImage(
            @Valid @RequestBody ImageEditRequest request,
            @Parameter(hidden = true) Authentication authentication) {

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

}
