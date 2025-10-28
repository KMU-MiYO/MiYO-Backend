package io.github.herbpot.miyobackend.domain.image.service;

import io.github.herbpot.miyobackend.domain.image.dto.ImageGenerationRequest;
import io.github.herbpot.miyobackend.domain.image.dto.ImageGenerationResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * GeminiImageService 테스트 (외부 API 모킹)
 */
@SpringBootTest
@ActiveProfiles("test")
class GeminiImageServiceTest {

    @Autowired
    private GeminiImageService geminiImageService;

    @MockBean
    private RestTemplate restTemplate;

    @MockBean
    private NCPObjectStorageService ncpObjectStorageService;

    private ImageGenerationRequest request;

    @BeforeEach
    void setUp() {
        request = ImageGenerationRequest.builder()
                .prompt("A beautiful sunset over the ocean")
                .numberOfImages(1)
                .aspectRatio("1:1")
                .build();
    }

    @Test
    @DisplayName("이미지 생성 및 NCP 업로드 성공")
    void generateAndUploadImage_Success() {
        // given
        String mockBase64Image = "mockBase64ImageData";
        String mockUploadedUrl = "https://contest90-image-bucket.kr.object.ncloudstorage.com/generate/test-image.png";

        // Mock Gemini API response
        when(restTemplate.postForObject(anyString(), any(), eq(String.class)))
                .thenReturn("{\"candidates\":[{\"content\":{\"parts\":[{\"inlineData\":{\"data\":\"" + mockBase64Image + "\"}}]}}]}");

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
        verify(restTemplate, times(1)).postForObject(anyString(), any(), eq(String.class));
        verify(ncpObjectStorageService, times(1)).uploadBase64Image(eq(mockBase64Image), eq("image/png"));
    }

    @Test
    @DisplayName("여러 이미지 생성 및 업로드 성공")
    void generateAndUploadMultipleImages_Success() {
        // given
        ImageGenerationRequest multiRequest = ImageGenerationRequest.builder()
                .prompt("Test prompt")
                .numberOfImages(3)
                .aspectRatio("1:1")
                .build();

        String mockBase64Image = "mockBase64ImageData";
        String mockUploadedUrl1 = "https://example.com/image1.png";
        String mockUploadedUrl2 = "https://example.com/image2.png";
        String mockUploadedUrl3 = "https://example.com/image3.png";

        // Mock Gemini API response
        when(restTemplate.postForObject(anyString(), any(), eq(String.class)))
                .thenReturn("{\"candidates\":[{\"content\":{\"parts\":[{\"inlineData\":{\"data\":\"" + mockBase64Image + "\"}}]}}]}");

        // Mock NCP upload (different URLs for each call)
        when(ncpObjectStorageService.uploadBase64Image(eq(mockBase64Image), eq("image/png")))
                .thenReturn(mockUploadedUrl1, mockUploadedUrl2, mockUploadedUrl3);

        // when
        ImageGenerationResponse response = geminiImageService.generateAndUploadImage(multiRequest);

        // then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getImages()).hasSize(3);
        assertThat(response.getImages()).containsExactly(mockUploadedUrl1, mockUploadedUrl2, mockUploadedUrl3);

        // Verify interactions
        verify(restTemplate, times(3)).postForObject(anyString(), any(), eq(String.class));
        verify(ncpObjectStorageService, times(3)).uploadBase64Image(eq(mockBase64Image), eq("image/png"));
    }

    @Test
    @DisplayName("Gemini API 호출 실패 시 실패 응답 반환")
    void generateAndUploadImage_GeminiApiFailed() {
        // given
        when(restTemplate.postForObject(anyString(), any(), eq(String.class)))
                .thenThrow(new RuntimeException("Gemini API connection failed"));

        // when
        ImageGenerationResponse response = geminiImageService.generateAndUploadImage(request);

        // then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getErrorMessage()).contains("이미지 생성 실패");

        // Verify NCP service was not called
        verify(ncpObjectStorageService, never()).uploadBase64Image(anyString(), anyString());
    }

    @Test
    @DisplayName("NCP 업로드 실패 시 실패 응답 반환")
    void generateAndUploadImage_NCPUploadFailed() {
        // given
        String mockBase64Image = "mockBase64ImageData";

        // Mock Gemini API success
        when(restTemplate.postForObject(anyString(), any(), eq(String.class)))
                .thenReturn("{\"candidates\":[{\"content\":{\"parts\":[{\"inlineData\":{\"data\":\"" + mockBase64Image + "\"}}]}}]}");

        // Mock NCP upload failure
        when(ncpObjectStorageService.uploadBase64Image(eq(mockBase64Image), eq("image/png")))
                .thenThrow(new RuntimeException("NCP upload failed"));

        // when
        ImageGenerationResponse response = geminiImageService.generateAndUploadImage(request);

        // then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getErrorMessage()).contains("이미지 업로드 실패");
    }

    @Test
    @DisplayName("잘못된 요청 파라미터 검증")
    void generateAndUploadImage_InvalidRequest() {
        // given
        ImageGenerationRequest invalidRequest = ImageGenerationRequest.builder()
                .prompt("")  // Empty prompt
                .numberOfImages(0)  // Invalid count
                .build();

        // when
        ImageGenerationResponse response = geminiImageService.generateAndUploadImage(invalidRequest);

        // then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getErrorMessage()).isNotBlank();

        // Verify no external calls were made
        verify(restTemplate, never()).postForObject(anyString(), any(), eq(String.class));
        verify(ncpObjectStorageService, never()).uploadBase64Image(anyString(), anyString());
    }
}
