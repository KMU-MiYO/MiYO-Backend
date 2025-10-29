package io.github.herbpot.miyobackend.common.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.io.IOException;
import java.util.Base64;
import java.util.UUID;

/**
 * NCPObjectStorageService
 * - NCP Object Storage 파일 업로드/삭제 서비스
 * - MultipartFile 업로드
 * - Base64 이미지 데이터 업로드 (Gemini 생성 이미지)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class NCPObjectStorageService {

    private final S3Client s3Client;

    @Value("${ncp.directory}")
    private String directory;

    @Value("${ncp.bucket-name}")
    private String bucketName;

    /**
     * MultipartFile 업로드
     *
     * @param file 업로드할 파일
     * @return 업로드된 파일의 공개 URL
     */
    public String uploadFile(MultipartFile file) {
        try {
            String fileName = directory + file.getOriginalFilename();

            // S3 업로드 요청 생성 (public-read ACL 설정)
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(fileName)
                    .contentType(file.getContentType())
                    .acl(ObjectCannedACL.PUBLIC_READ)
                    .build();

            // 파일 업로드 실행
            s3Client.putObject(putObjectRequest, RequestBody.fromBytes(file.getBytes()));

            // 업로드된 파일의 URL 반환
            String url = "https://" + bucketName + ".kr.object.ncloudstorage.com/" + fileName;
            log.info("File uploaded successfully: {}", url);
            return url;

        } catch (IOException e) {
            log.error("Failed to upload file", e);
            throw new RuntimeException("파일 업로드 실패", e);
        }
    }

    /**
     * Base64 인코딩된 이미지 업로드 (Gemini AI 생성 이미지)
     *
     * @param base64Image Base64 인코딩된 이미지 데이터
     * @param contentType 이미지 MIME 타입 (예: image/png, image/jpeg)
     * @return 업로드된 파일의 공개 URL
     */
    public String uploadBase64Image(String base64Image, String contentType) {
        try {
            // Base64 디코딩
            byte[] imageBytes = Base64.getDecoder().decode(base64Image);

            // 파일명 생성 (UUID + 확장자)
            String extension = getExtensionFromContentType(contentType);
            String fileName = directory + UUID.randomUUID().toString() + extension;

            log.info("Uploading Base64 image: fileName={}, size={} bytes", fileName, imageBytes.length);

            // S3 업로드 요청 생성 (public-read ACL 설정)
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(fileName)
                    .contentType(contentType)
                    .contentLength((long) imageBytes.length)
                    .acl(ObjectCannedACL.PUBLIC_READ)
                    .build();

            // 파일 업로드 실행
            s3Client.putObject(putObjectRequest, RequestBody.fromBytes(imageBytes));

            // 업로드된 파일의 URL 반환
            String url = "https://" + bucketName + ".kr.object.ncloudstorage.com/" + fileName;
            log.info("Base64 image uploaded successfully: {}", url);
            return url;

        } catch (IllegalArgumentException e) {
            log.error("Invalid Base64 format", e);
            throw new RuntimeException("잘못된 Base64 이미지 형식입니다", e);
        } catch (S3Exception e) {
            log.error("Failed to upload Base64 image to NCP", e);
            throw new RuntimeException("이미지 업로드 실패", e);
        }
    }

    /**
     * 파일 삭제
     *
     * @param fileName 삭제할 파일명
     */
    public void removeFile(String fileName) {
        try {
            DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                    .bucket(bucketName)
                    .key(directory + fileName)
                    .build();

            s3Client.deleteObject(deleteObjectRequest);
            log.info("File deleted successfully: {}", fileName);

        } catch (S3Exception e) {
            log.error("Failed to delete file: {}", fileName, e);
            throw new RuntimeException("파일 삭제 실패", e);
        }
    }

    /**
     * URL에서 파일 삭제
     *
     * @param fileUrl 파일의 전체 URL
     */
    public void removeFileByUrl(String fileUrl) {
        try {
            // URL에서 파일명 추출
            // 예: https://contest90-image-bucket.kr.object.ncloudstorage.com/images/abc.png
            // -> images/abc.png
            String key = extractKeyFromUrl(fileUrl);

            DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .build();

            s3Client.deleteObject(deleteObjectRequest);
            log.info("File deleted successfully by URL: {}", fileUrl);

        } catch (S3Exception e) {
            log.error("Failed to delete file by URL: {}", fileUrl, e);
            throw new RuntimeException("파일 삭제 실패", e);
        }
    }

    /**
     * Content-Type에서 파일 확장자 추출
     */
    private String getExtensionFromContentType(String contentType) {
        if (contentType == null) {
            return ".png"; // 기본값
        }

        return switch (contentType.toLowerCase()) {
            case "image/png" -> ".png";
            case "image/jpeg", "image/jpg" -> ".jpg";
            case "image/gif" -> ".gif";
            case "image/webp" -> ".webp";
            default -> ".png";
        };
    }

    /**
     * URL에서 Object Storage Key 추출
     */
    private String extractKeyFromUrl(String fileUrl) {
        // https://contest90-image-bucket.kr.object.ncloudstorage.com/images/abc.png
        // -> images/abc.png
        String[] parts = fileUrl.split(".kr.object.ncloudstorage.com/");
        if (parts.length > 1) {
            return parts[1];
        }
        throw new IllegalArgumentException("Invalid file URL format: " + fileUrl);
    }
}
