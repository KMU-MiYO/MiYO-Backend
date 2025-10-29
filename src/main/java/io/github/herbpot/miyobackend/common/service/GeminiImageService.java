package io.github.herbpot.miyobackend.common.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.herbpot.miyobackend.common.dto.ImageEditRequest;
import io.github.herbpot.miyobackend.common.dto.ImageGenerationRequest;
import io.github.herbpot.miyobackend.common.dto.ImageGenerationResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * GeminiImageService
 * - Google Gemini AI (Imagen 3 Fast) 이미지 생성 서비스
 * - 생성된 이미지를 NCP Object Storage에 자동 업로드
 * - Post와 Contest 도메인에서 공통으로 사용
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GeminiImageService {

    @Value("${gemini.api-key}")
    private String apiKey;

    @Value("${gemini.api-url}")
    private String apiUrl;

    private final NCPObjectStorageService ncpObjectStorageService;
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 이미지 생성 (Base64 반환) - Google AI Studio 방식
     *
     * @param request 이미지 생성 요청
     * @return 생성된 이미지 응답 (Base64 데이터)
     */
    public ImageGenerationResponse generateImage(ImageGenerationRequest request) {
        log.info("Generating image with Gemini AI: prompt={}", request.getPrompt());

        try {
            // Gemini API 요청 본문 구성
            Map<String, Object> requestBody = buildRequestBody(request);

            // HTTP 헤더 설정
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("x-goog-api-key", apiKey);

            HttpEntity<Map<String, Object>> httpEntity = new HttpEntity<>(requestBody, headers);

            // Gemini API 호출
            String url = apiUrl + "?key=" + apiKey;
            ResponseEntity<String> response = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    httpEntity,
                    String.class
            );

            // 응답 파싱
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                List<String> images = parseImages(response.getBody());
                log.info("Image generation successful: {} images generated", images.size());
                return ImageGenerationResponse.success(images, request.getPrompt());
            } else {
                log.error("Image generation failed: status={}", response.getStatusCode());
                return ImageGenerationResponse.failure(
                        "이미지 생성에 실패했습니다.",
                        request.getPrompt()
                );
            }

        } catch (Exception e) {
            log.error("Error generating image with Gemini AI", e);
            return ImageGenerationResponse.failure(
                    "이미지 생성 중 오류가 발생했습니다: " + e.getMessage(),
                    request.getPrompt()
            );
        }
    }

    /**
     * 이미지 생성 및 NCP Object Storage 업로드
     *
     * @param request 이미지 생성 요청
     * @return 생성된 이미지 응답 (NCP URL)
     */
    public ImageGenerationResponse generateAndUploadImage(ImageGenerationRequest request) {
        log.info("Generating and uploading image: prompt={}", request.getPrompt());

        try {
            // 1. Gemini AI로 이미지 생성
            ImageGenerationResponse generationResponse = generateImage(request);

            if (!generationResponse.isSuccess() || generationResponse.getImages().isEmpty()) {
                return generationResponse;
            }

            // 2. 생성된 이미지들을 NCP Object Storage에 업로드
            List<String> uploadedUrls = new ArrayList<>();
            log.info("Starting NCP upload for {} images", generationResponse.getImages().size());

            for (int i = 0; i < generationResponse.getImages().size(); i++) {
                String base64Image = generationResponse.getImages().get(i);
                try {
                    log.info("Uploading image {} to NCP (Base64 length: {})", i + 1, base64Image.length());

                    // Base64 이미지를 NCP에 업로드
                    String uploadedUrl = ncpObjectStorageService.uploadBase64Image(
                            base64Image,
                            "image/png" // Gemini는 기본적으로 PNG 형식
                    );
                    uploadedUrls.add(uploadedUrl);
                    log.info("Image {} uploaded successfully to NCP: {}", i + 1, uploadedUrl);
                } catch (Exception e) {
                    log.error("Failed to upload image {} to NCP: {}", i + 1, e.getMessage(), e);
                    // 업로드 실패한 이미지는 건너뛰고 계속 진행
                }
            }

            if (uploadedUrls.isEmpty()) {
                return ImageGenerationResponse.failure(
                        "이미지 업로드에 실패했습니다.",
                        request.getPrompt()
                );
            }

            log.info("Successfully generated and uploaded {} images", uploadedUrls.size());
            return ImageGenerationResponse.success(uploadedUrls, request.getPrompt());

        } catch (Exception e) {
            log.error("Error generating and uploading image", e);
            return ImageGenerationResponse.failure(
                    "이미지 생성 및 업로드 중 오류가 발생했습니다: " + e.getMessage(),
                    request.getPrompt()
            );
        }
    }

    /**
     * Gemini API 요청 본문 구성 (Google AI Studio 방식)
     * REQUIREMENTS.md 형식 - gemini-2.5-flash-image 모델 사용
     */
    private Map<String, Object> buildRequestBody(ImageGenerationRequest request) {
        Map<String, Object> body = new HashMap<>();

        // contents 배열 생성
        List<Map<String, Object>> contents = new ArrayList<>();
        Map<String, Object> content = new HashMap<>();

        // parts 배열 생성
        List<Map<String, String>> parts = new ArrayList<>();
        Map<String, String> part = new HashMap<>();
        part.put("text", request.getPrompt());
        parts.add(part);

        content.put("parts", parts);
        contents.add(content);

        body.put("contents", contents);

        return body;
    }

    /**
     * API 응답에서 이미지 데이터 추출
     * Google AI Studio Gemini 응답 형식:
     * {
     *   "candidates": [{
     *     "content": {
     *       "parts": [{
     *         "inlineData": {
     *           "mimeType": "image/png",
     *           "data": "base64_encoded_image..."
     *         }
     *       }]
     *     }
     *   }]
     * }
     */
    private List<String> parseImages(String responseBody) throws Exception {
        List<String> images = new ArrayList<>();

        JsonNode root = objectMapper.readTree(responseBody);
        log.debug("Gemini API Response: {}", responseBody);

        // Gemini 2.5 Flash 이미지 생성 응답 구조
        JsonNode candidates = root.get("candidates");

        if (candidates != null && candidates.isArray()) {
            for (JsonNode candidate : candidates) {
                JsonNode content = candidate.get("content");
                if (content != null) {
                    JsonNode parts = content.get("parts");
                    if (parts != null && parts.isArray()) {
                        for (JsonNode part : parts) {
                            // inline_data 또는 inlineData에서 base64 이미지 추출 (둘 다 시도)
                            JsonNode inlineData = part.get("inline_data");
                            if (inlineData == null) {
                                inlineData = part.get("inlineData");
                            }
                            if (inlineData != null) {
                                JsonNode data = inlineData.get("data");
                                if (data != null) {
                                    images.add(data.asText());
                                    log.info("Extracted image data from inline_data/inlineData");
                                }
                            }
                        }
                    }
                }
            }
        }

        if (images.isEmpty()) {
            log.warn("No images found in response. Response body: {}", responseBody);
        }

        return images;
    }

    /**
     * 이미지 기반 이미지 생성 (이미지 URL + 프롬프트)
     *
     * @param request 이미지 편집 요청
     * @return 생성된 이미지 응답 (Base64 데이터)
     */
    public ImageGenerationResponse generateImageFromImage(ImageEditRequest request) {
        log.info("Generating image from image: imageUrl={}, prompt={}", request.getImageUrl(), request.getPrompt());

        try {
            // 1. 이미지 URL에서 이미지 다운로드 및 Base64 인코딩
            String base64Image = downloadAndEncodeImage(request.getImageUrl());

            // 이미지 MIME 타입 추론
            String mimeType = getMimeTypeFromUrl(request.getImageUrl());

            // 2. Gemini API 요청 본문 구성 (이미지 포함)
            Map<String, Object> requestBody = buildRequestBodyWithImage(request, base64Image, mimeType);

            // 3. HTTP 헤더 설정
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("x-goog-api-key", apiKey);

            HttpEntity<Map<String, Object>> httpEntity = new HttpEntity<>(requestBody, headers);

            // 4. Gemini API 호출
            String url = apiUrl + "?key=" + apiKey;
            ResponseEntity<String> response = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    httpEntity,
                    String.class
            );

            // 5. 응답 파싱
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                List<String> images = parseImages(response.getBody());
                log.info("Image generation from image successful: {} images generated", images.size());
                return ImageGenerationResponse.success(images, request.getPrompt());
            } else {
                log.error("Image generation from image failed: status={}", response.getStatusCode());
                return ImageGenerationResponse.failure(
                        "이미지 생성에 실패했습니다.",
                        request.getPrompt()
                );
            }

        } catch (Exception e) {
            log.error("Error generating image from image", e);
            return ImageGenerationResponse.failure(
                    "이미지 생성 중 오류가 발생했습니다: " + e.getMessage(),
                    request.getPrompt()
            );
        }
    }

    /**
     * 이미지 기반 이미지 생성 및 NCP 업로드
     *
     * @param request 이미지 편집 요청
     * @return 생성된 이미지 응답 (NCP URL)
     */
    public ImageGenerationResponse generateAndUploadImageFromImage(ImageEditRequest request) {
        log.info("Generating and uploading image from image: imageUrl={}, prompt={}",
                request.getImageUrl(), request.getPrompt());

        try {
            // 1. 이미지 기반 이미지 생성
            ImageGenerationResponse generationResponse = generateImageFromImage(request);

            if (!generationResponse.isSuccess() || generationResponse.getImages().isEmpty()) {
                return generationResponse;
            }

            // 2. 생성된 이미지들을 NCP Object Storage에 업로드
            List<String> uploadedUrls = new ArrayList<>();
            log.info("Starting NCP upload for {} images", generationResponse.getImages().size());

            for (int i = 0; i < generationResponse.getImages().size(); i++) {
                String base64Image = generationResponse.getImages().get(i);
                try {
                    log.info("Uploading image {} to NCP (Base64 length: {})", i + 1, base64Image.length());

                    // Base64 이미지를 NCP에 업로드
                    String uploadedUrl = ncpObjectStorageService.uploadBase64Image(
                            base64Image,
                            "image/png"
                    );
                    uploadedUrls.add(uploadedUrl);
                    log.info("Image {} uploaded successfully to NCP: {}", i + 1, uploadedUrl);
                } catch (Exception e) {
                    log.error("Failed to upload image {} to NCP: {}", i + 1, e.getMessage(), e);
                }
            }

            if (uploadedUrls.isEmpty()) {
                return ImageGenerationResponse.failure(
                        "이미지 업로드에 실패했습니다.",
                        request.getPrompt()
                );
            }

            log.info("Successfully generated and uploaded {} images from source image", uploadedUrls.size());
            return ImageGenerationResponse.success(uploadedUrls, request.getPrompt());

        } catch (Exception e) {
            log.error("Error generating and uploading image from image", e);
            return ImageGenerationResponse.failure(
                    "이미지 생성 및 업로드 중 오류가 발생했습니다: " + e.getMessage(),
                    request.getPrompt()
            );
        }
    }

    /**
     * 이미지 URL에서 이미지 다운로드 및 Base64 인코딩
     */
    private String downloadAndEncodeImage(String imageUrl) throws IOException {
        log.info("Downloading image from URL: {}", imageUrl);

        URL url = new URL(imageUrl);
        byte[] imageBytes = url.openStream().readAllBytes();

        String base64 = Base64.getEncoder().encodeToString(imageBytes);
        log.info("Image downloaded and encoded: {} bytes", imageBytes.length);

        return base64;
    }

    /**
     * 이미지를 포함한 Gemini API 요청 본문 구성
     */
    private Map<String, Object> buildRequestBodyWithImage(ImageEditRequest request, String base64Image, String mimeType) {
        Map<String, Object> body = new HashMap<>();

        // contents 배열 생성
        List<Map<String, Object>> contents = new ArrayList<>();
        Map<String, Object> content = new HashMap<>();

        // parts 배열 생성 (텍스트 + 이미지)
        List<Map<String, Object>> parts = new ArrayList<>();

        // 1. 텍스트 파트 (프롬프트)
        Map<String, Object> textPart = new HashMap<>();
        textPart.put("text", request.getPrompt());
        parts.add(textPart);

        // 2. 이미지 파트 (inline_data)
        Map<String, Object> imagePart = new HashMap<>();
        Map<String, String> inlineData = new HashMap<>();
        inlineData.put("mime_type", mimeType);
        inlineData.put("data", base64Image);
        imagePart.put("inline_data", inlineData);
        parts.add(imagePart);

        content.put("parts", parts);
        contents.add(content);

        body.put("contents", contents);

        return body;
    }

    /**
     * URL에서 MIME 타입 추론
     */
    private String getMimeTypeFromUrl(String imageUrl) {
        String lowerUrl = imageUrl.toLowerCase();
        if (lowerUrl.endsWith(".jpg") || lowerUrl.endsWith(".jpeg")) {
            return "image/jpeg";
        } else if (lowerUrl.endsWith(".png")) {
            return "image/png";
        } else if (lowerUrl.endsWith(".gif")) {
            return "image/gif";
        } else if (lowerUrl.endsWith(".webp")) {
            return "image/webp";
        }
        // 기본값은 PNG
        return "image/png";
    }
}
