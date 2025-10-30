package io.github.herbpot.miyobackend.client;

import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

/**
 * User Service HTTP Client
 * - user-service와 HTTP 통신하여 사용자 정보 조회
 * - MSA 환경에서 서비스 간 통신 담당
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserServiceClient {

    private final RestTemplate restTemplate;

    @Value("${user-service.url}")
    private String userServiceUrl;

    /**
     * 사용자 닉네임 조회
     * @param userId 사용자 ID
     * @return 닉네임 (조회 실패 시 "Unknown")
     */
    public String getUserNickname(String userId) {
        try {
            String url = userServiceUrl + "/users/" + userId;
            log.debug("Fetching user info from user-service: userId={}", userId);

            // user-service에 HTTP GET 요청
            UserResponse response = restTemplate.getForObject(url, UserResponse.class);

            if (response != null && response.getNickname() != null) {
                log.debug("User info fetched successfully: userId={}, nickname={}", userId, response.getNickname());
                return response.getNickname();
            } else {
                log.warn("User nickname not found: userId={}", userId);
                return "Unknown";
            }
        } catch (Exception e) {
            log.error("Failed to fetch user info from user-service: userId={}", userId, e);
            return "Unknown";
        }
    }

    /**
     * User Service 응답 DTO
     */
    @Getter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class UserResponse {
        private String nickname;

    }
}
