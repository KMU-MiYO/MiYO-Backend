package io.github.herbpot.miyobackend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import java.net.URI;

/**
 * NCP Object Storage Configuration
 * - AWS S3 SDK를 사용하여 NCP Object Storage 연동
 * - S3Client Bean 생성
 */
@Configuration
public class NCPObjectStorageConfig {

    @Value("${ncp.access-key}")
    private String accessKey;

    @Value("${ncp.secret-key}")
    private String secretKey;

    @Value("${ncp.endpoint}")
    private String endpoint;

    @Value("${ncp.region}")
    private String region;

    /**
     * S3Client Bean 생성
     * - NCP Object Storage 엔드포인트로 연결
     * - AWS SDK S3 호환 방식 사용
     */
    @Bean
    public S3Client s3Client() {
        AwsBasicCredentials credentials = AwsBasicCredentials.create(accessKey, secretKey);

        return S3Client.builder()
                .endpointOverride(URI.create(endpoint))
                .credentialsProvider(StaticCredentialsProvider.create(credentials))
                .region(Region.of(region))
                .build();
    }
}
