package io.github.herbpot.miyobackend.client;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.CannedAccessControlList;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.UUID;

/**
 * NCP Object Storage Client
 * - NCP Object Storage에 이미지를 업로드하고 URL을 반환
 * - Base64 인코딩된 이미지를 디코딩하여 업로드
 * - S3 호환 API 사용
 */
@Slf4j
@Component
public class NCPObjectStorageClient {

    @Value("${ncp.object-storage.endpoint}")
    private String endpoint;

    @Value("${ncp.object-storage.region}")
    private String region;

    @Value("${ncp.object-storage.access-key}")
    private String accessKey;

    @Value("${ncp.object-storage.secret-key}")
    private String secretKey;

    @Value("${ncp.object-storage.bucket-name}")
    private String bucketName;

    private AmazonS3 s3Client;

    /**
     * AmazonS3 Client 초기화
     * - NCP Object Storage는 S3 호환 API 제공
     */
    @PostConstruct
    public void init() {
        BasicAWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);

        this.s3Client = AmazonS3ClientBuilder.standard()
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(endpoint, region))
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .build();

        log.info("NCP Object Storage client initialized: bucket={}", bucketName);
    }

    /**
     * Base64 인코딩된 이미지를 업로드하고 URL 반환
     *
     * @param base64Image Base64 인코딩된 이미지 문자열
     * @param originalFilename 원본 파일명 (확장자 추출용, null 가능)
     * @return 업로드된 이미지의 공개 URL
     * @throws IllegalArgumentException Base64 디코딩 실패 시
     */
    public String uploadBase64Image(String base64Image, String originalFilename) {
        try {
            log.info("Uploading base64 image to NCP Object Storage");

            // Base64 디코딩
            byte[] imageBytes = decodeBase64(base64Image);

            // 파일명 생성 (UUID + 확장자)
            String fileName = generateFileName(originalFilename);

            // 메타데이터 설정
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(imageBytes.length);
            metadata.setContentType(determineContentType(fileName));

            // S3에 업로드
            ByteArrayInputStream inputStream = new ByteArrayInputStream(imageBytes);
            PutObjectRequest putObjectRequest = new PutObjectRequest(
                    bucketName,
                    fileName,
                    inputStream,
                    metadata
            ).withCannedAcl(CannedAccessControlList.PublicRead); // 공개 읽기 권한

            s3Client.putObject(putObjectRequest);

            // URL 생성
            String imageUrl = String.format("%s/%s/%s", endpoint, bucketName, fileName);
            log.info("Image uploaded successfully: url={}", imageUrl);

            return imageUrl;

        } catch (Exception e) {
            log.error("Failed to upload image to NCP Object Storage", e);
            throw new RuntimeException("이미지 업로드에 실패했습니다: " + e.getMessage(), e);
        }
    }

    /**
     * Base64 문자열을 byte 배열로 디코딩
     * - Data URL scheme (data:image/png;base64,) 접두사 제거
     *
     * @param base64Image Base64 인코딩된 이미지 문자열
     * @return 디코딩된 byte 배열
     */
    private byte[] decodeBase64(String base64Image) {
        String base64Data = base64Image;

        // Data URL scheme 제거 (data:image/png;base64, 등)
        if (base64Image.contains(",")) {
            base64Data = base64Image.split(",")[1];
        }

        return Base64.getDecoder().decode(base64Data);
    }

    /**
     * 고유한 파일명 생성
     * - UUID + 타임스탬프 + 원본 확장자
     *
     * @param originalFilename 원본 파일명 (null 가능)
     * @return 생성된 파일명
     */
    private String generateFileName(String originalFilename) {
        String extension = ".jpg"; // 기본 확장자

        if (originalFilename != null && originalFilename.contains(".")) {
            extension = originalFilename.substring(originalFilename.lastIndexOf("."));
        }

        return String.format("images/%s-%d%s",
                UUID.randomUUID().toString(),
                System.currentTimeMillis(),
                extension);
    }

    /**
     * 파일 확장자에 따른 Content-Type 결정
     *
     * @param fileName 파일명
     * @return Content-Type
     */
    private String determineContentType(String fileName) {
        String lowerFileName = fileName.toLowerCase();

        if (lowerFileName.endsWith(".png")) {
            return "image/png";
        } else if (lowerFileName.endsWith(".jpg") || lowerFileName.endsWith(".jpeg")) {
            return "image/jpeg";
        } else if (lowerFileName.endsWith(".gif")) {
            return "image/gif";
        } else if (lowerFileName.endsWith(".webp")) {
            return "image/webp";
        } else {
            return "application/octet-stream";
        }
    }
}
