package io.github.herbpot.miyobackend.common.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.herbpot.miyobackend.common.dto.ImageGenerationRequest;
import io.github.herbpot.miyobackend.common.dto.ImageGenerationResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
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
     * 이미지 생성 (Base64만 반환)
     *
     * @param request 이미지 생성 요청
     * @return 생성된 이미지 응답 (Base64 데이터)
     */
    public ImageGenerationResponse generateImage(ImageGenerationRequest request) {
        log.info("Generating image with Gemini AI: prompt={}", request.getPrompt());

        try {
            // Gemini API 요청 본문 구성
            Map<String, Object> requestBody = buildRequestBody(request);

            // HTTP 헤더 설정 (API Key는 쿼리 파라미터로 전달)
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> httpEntity = new HttpEntity<>(requestBody, headers);

            // Gemini API 호출 (API Key를 쿼리 파라미터로 추가)
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
            for (String base64Image : generationResponse.getImages()) {
                try {
                    // Base64 이미지를 NCP에 업로드
                    String uploadedUrl = ncpObjectStorageService.uploadBase64Image(
                            base64Image,
                            "image/png" // Gemini는 기본적으로 PNG 형식
                    );
                    uploadedUrls.add(uploadedUrl);
                    log.info("Image uploaded to NCP: {}", uploadedUrl);
                } catch (Exception e) {
                    log.error("Failed to upload image to NCP", e);
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
     * Gemini Imagen API 요청 본문 구성
     * generativelanguage.googleapis.com 형식에 맞춰 구성
     */
    private Map<String, Object> buildRequestBody(ImageGenerationRequest request) {
        Map<String, Object> body = new HashMap<>();

        // prompt 설정
        body.put("prompt", request.getPrompt());

        // numberOfImages 설정
        body.put("numberOfImages", request.getNumberOfImages());

        // 이미지 크기 설정
        // Gemini Imagen은 특정 크기만 지원 (예: 256x256, 512x512, 1024x1024, 1536x1536)
        String[] size = request.getSize().split("x");
        if (size.length == 2) {
            try {
                int width = Integer.parseInt(size[0]);
                int height = Integer.parseInt(size[1]);

                // aspectRatio 또는 특정 크기 지정
                Map<String, Object> imageSize = new HashMap<>();
                imageSize.put("width", width);
                imageSize.put("height", height);
                body.put("imageSize", imageSize);
            } catch (NumberFormatException e) {
                // 기본값 사용 (1024x1024)
                Map<String, Object> imageSize = new HashMap<>();
                imageSize.put("width", 1024);
                imageSize.put("height", 1024);
                body.put("imageSize", imageSize);
            }
        }

        return body;
    }

    /**
     * API 응답에서 이미지 데이터 추출
     * Gemini Imagen API 응답 형식: { "generatedImages": [{ "generatedImage": "base64..." }] }
     */
    private List<String> parseImages(String responseBody) throws Exception {
        List<String> images = new ArrayList<>();

        JsonNode root = objectMapper.readTree(responseBody);

        // Gemini Imagen API 응답 구조
        JsonNode generatedImages = root.get("generatedImages");

        if (generatedImages != null && generatedImages.isArray()) {
            for (JsonNode imageNode : generatedImages) {
                // Base64 인코딩된 이미지 데이터
                JsonNode generatedImage = imageNode.get("generatedImage");
                if (generatedImage != null) {
                    images.add(generatedImage.asText());
                }

                // 또는 bytesBase64Encoded 필드 (응답 구조에 따라)
                JsonNode bytesBase64 = imageNode.get("bytesBase64Encoded");
                if (bytesBase64 != null) {
                    images.add(bytesBase64.asText());
                }
            }
        }

        // 예전 응답 형식 지원 (호환성)
        JsonNode predictions = root.get("predictions");
        if (predictions != null && predictions.isArray()) {
            for (JsonNode prediction : predictions) {
                JsonNode bytesBase64Encoded = prediction.get("bytesBase64Encoded");
                if (bytesBase64Encoded != null) {
                    images.add(bytesBase64Encoded.asText());
                }
            }
        }

        return images;
    }
}
