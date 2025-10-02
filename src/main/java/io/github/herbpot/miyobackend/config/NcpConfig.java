package io.github.herbpot.miyobackend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import java.net.URI;

@Configuration
public class NcpConfig {
    @Value("${ncp.access-key}")
    private String accessKey;

    @Value("${ncp.secret-key}")
    private String secretKey;

    @Bean
    public S3Client s3Client() {
        return S3Client.builder()
                .region(Region.of("kr-standard"))  // 네이버 클라우드는 "kr-standard" 사용
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKey, secretKey)
                ))
                .endpointOverride(URI.create("https://kr.object.ncloudstorage.com"))
                .build();
    }
}
