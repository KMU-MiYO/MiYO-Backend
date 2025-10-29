package io.github.herbpot.miyobackend.domain.image.service;

import io.github.herbpot.miyobackend.common.service.GeminiImageService;
import io.github.herbpot.miyobackend.common.service.NCPObjectStorageService;
import io.github.herbpot.miyobackend.common.dto.ImageGenerationRequest;
import io.github.herbpot.miyobackend.common.dto.ImageGenerationResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * GeminiImageService 테스트 (외부 API 모킹)
 */
@ExtendWith(MockitoExtension.class)
class GeminiImageServiceTest {

    @Mock
    private NCPObjectStorageService ncpObjectStorageService;

    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    private GeminiImageService geminiImageService;

    private ImageGenerationRequest request;

    @BeforeEach
    void setUp() {
        // Set Gemini API configuration via ReflectionTestUtils
        ReflectionTestUtils.setField(geminiImageService, "apiKey", "test-api-key");
        ReflectionTestUtils.setField(geminiImageService, "apiUrl", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image:generateContent");

        // Create request using constructor (no builder)
        request = new ImageGenerationRequest(
                "A beautiful sunset over the ocean",
                1,
                "1024x1024"
        );
    }

    @Test
    @DisplayName("이미지 생성 및 NCP 업로드 성공")
    void generateAndUploadImage_Success() {
        // given
        String mockBase64Image = "mockBase64ImageData";
        String mockUploadedUrl = "https://contest90-image-bucket.kr.object.ncloudstorage.com/generate/test-image.png";
        String mockGeminiResponse = "{\"candidates\":[{\"content\":{\"parts\":[{\"inlineData\":{\"data\":\"" + mockBase64Image + "\"}}]}}]}";

        // Mock Gemini API response
        ResponseEntity<String> responseEntity = new ResponseEntity<>(mockGeminiResponse, HttpStatus.OK);
        when(restTemplate.exchange(anyString(), any(), any(), eq(String.class)))
                .thenReturn(responseEntity);

        // Mock NCP upload
        when(ncpObjectStorageService.uploadBase64Image(eq(mockBase64Image), eq("image/png")))
                .thenReturn(mockUploadedUrl);

        // when
        ImageGenerationResponse response = geminiImageService.generateAndUploadImage(request);

        // then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getImages()).hasSize(1);
        assertThat(response.getImages().get(0)).isEqualTo(mockUploadedUrl);
        assertThat(response.getPrompt()).isEqualTo("A beautiful sunset over the ocean");

        // Verify interactions
        verify(restTemplate, times(1)).exchange(anyString(), any(), any(), eq(String.class));
        verify(ncpObjectStorageService, times(1)).uploadBase64Image(eq(mockBase64Image), eq("image/png"));
    }

    @Test
    @DisplayName("이미지 생성 성공")
    void generateImage_Success() {
        // given
        String mockBase64Image = "mockBase64ImageData";
        String mockGeminiResponse = "{\"candidates\":[{\"content\":{\"parts\":[{\"inlineData\":{\"data\":\"" + mockBase64Image + "\"}}]}}]}";

        // Mock Gemini API response
        ResponseEntity<String> responseEntity = new ResponseEntity<>(mockGeminiResponse, HttpStatus.OK);
        when(restTemplate.exchange(anyString(), any(), any(), eq(String.class)))
                .thenReturn(responseEntity);

        // when
        ImageGenerationResponse response = geminiImageService.generateImage(request);

        // then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getImages()).hasSize(1);
        assertThat(response.getImages().get(0)).isEqualTo(mockBase64Image);
        assertThat(response.getPrompt()).isEqualTo("A beautiful sunset over the ocean");

        // Verify interactions
        verify(restTemplate, times(1)).exchange(anyString(), any(), any(), eq(String.class));
    }

    @Test
    @DisplayName("Gemini API 호출 실패 시 실패 응답 반환")
    void generateAndUploadImage_GeminiApiFailed() {
        // given
        when(restTemplate.exchange(anyString(), any(), any(), eq(String.class)))
                .thenThrow(new RuntimeException("Gemini API connection failed"));

        // when
        ImageGenerationResponse response = geminiImageService.generateAndUploadImage(request);

        // then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getErrorMessage()).contains("이미지 생성");

        // Verify NCP service was not called
        verify(ncpObjectStorageService, never()).uploadBase64Image(anyString(), anyString());
    }

    @Test
    @DisplayName("NCP 업로드 실패 시 실패 응답 반환")
    void generateAndUploadImage_NCPUploadFailed() {
        // given
        String mockBase64Image = "mockBase64ImageData";
        String mockGeminiResponse = "{\"candidates\":[{\"content\":{\"parts\":[{\"inlineData\":{\"data\":\"" + mockBase64Image + "\"}}]}}]}";

        // Mock Gemini API success
        ResponseEntity<String> responseEntity = new ResponseEntity<>(mockGeminiResponse, HttpStatus.OK);
        when(restTemplate.exchange(anyString(), any(), any(), eq(String.class)))
                .thenReturn(responseEntity);

        // Mock NCP upload failure
        when(ncpObjectStorageService.uploadBase64Image(eq(mockBase64Image), eq("image/png")))
                .thenThrow(new RuntimeException("NCP upload failed"));

        // when
        ImageGenerationResponse response = geminiImageService.generateAndUploadImage(request);

        // then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getErrorMessage()).contains("이미지 업로드");
    }
}
