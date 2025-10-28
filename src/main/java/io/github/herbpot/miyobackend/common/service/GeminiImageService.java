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
     * Gemini API 요청 본문 구성
     */
    private Map<String, Object> buildRequestBody(ImageGenerationRequest request) {
        Map<String, Object> body = new HashMap<>();

        // 프롬프트 설정
        Map<String, String> prompt = new HashMap<>();
        prompt.put("text", request.getPrompt());
        body.put("prompt", prompt);

        // 이미지 생성 파라미터
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("sampleCount", request.getNumberOfImages());

        // 이미지 크기 파싱 (예: "1024x1024" -> width: 1024, height: 1024)
        String[] size = request.getSize().split("x");
        if (size.length == 2) {
            try {
                parameters.put("width", Integer.parseInt(size[0]));
                parameters.put("height", Integer.parseInt(size[1]));
            } catch (NumberFormatException e) {
                // 기본값 사용
                parameters.put("width", 1024);
                parameters.put("height", 1024);
            }
        }

        body.put("parameters", parameters);

        return body;
    }

    /**
     * API 응답에서 이미지 데이터 추출
     */
    private List<String> parseImages(String responseBody) throws Exception {
        List<String> images = new ArrayList<>();

        JsonNode root = objectMapper.readTree(responseBody);
        JsonNode predictions = root.get("predictions");

        if (predictions != null && predictions.isArray()) {
            for (JsonNode prediction : predictions) {
                // Base64 인코딩된 이미지 데이터
                JsonNode bytesBase64Encoded = prediction.get("bytesBase64Encoded");
                if (bytesBase64Encoded != null) {
                    images.add(bytesBase64Encoded.asText());
                }

                // 또는 이미지 URL (Gemini API 응답 구조에 따라 다를 수 있음)
                JsonNode imageUrl = prediction.get("imageUrl");
                if (imageUrl != null) {
                    images.add(imageUrl.asText());
                }
            }
        }

        return images;
    }
}
