package io.github.herbpot.miyobackend.client;

import io.github.herbpot.miyobackend.client.dto.RewardRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
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
     * @param token Authorization 토큰
     * @return 닉네임 (조회 실패 시 "Unknown")
     */
    public String getUserNickname(String userId, String token) {
        try {
            String url = userServiceUrl + "/users/" + userId;
            log.debug("Fetching user info from user-service: userId={}", userId);

            // Authorization 헤더 추가
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", token);
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            // user-service에 HTTP GET 요청
            ResponseEntity<UserResponse> responseEntity = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    entity,
                    UserResponse.class
            );

            UserResponse response = responseEntity.getBody();

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
     * 리워드 지급
     * @param userId 사용자 ID
     * @param rewardPoints 지급할 리워드 포인트
     * @throws Exception 리워드 지급 실패 시 예외 발생
     */
    public void addReward(String userId, Integer rewardPoints) {
        try {
            String url = userServiceUrl + "/v0/reward/insert";
            log.info("[UserServiceClient] Adding reward: userId={}, rewardPoints={}", userId, rewardPoints);

            // 요청 본문 생성
            RewardRequest request = RewardRequest.builder()
                    .userId(userId)
                    .reward(rewardPoints)
                    .build();

            // HTTP POST 요청
            ResponseEntity<Void> responseEntity = restTemplate.postForEntity(
                    url,
                    request,
                    Void.class
            );

            if (responseEntity.getStatusCode().is2xxSuccessful()) {
                log.info("[UserServiceClient] Reward added successfully: userId={}, rewardPoints={}",
                        userId, rewardPoints);
            } else {
                log.error("[UserServiceClient] Failed to add reward: userId={}, statusCode={}",
                        userId, responseEntity.getStatusCode());
                throw new RuntimeException("Failed to add reward: status=" + responseEntity.getStatusCode());
            }
        } catch (Exception e) {
            log.error("[UserServiceClient] Failed to add reward: userId={}, rewardPoints={}, error={}",
                    userId, rewardPoints, e.getMessage(), e);
            throw e; // 상위 레이어에서 에러 핸들링
        }
    }

    /**
     * User Service 응답 DTO
     */
    public static class UserResponse {
        private String id;
        private String nickname;
        private String email;

        public UserResponse() {}

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getNickname() {
            return nickname;
        }

        public void setNickname(String nickname) {
            this.nickname = nickname;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }
    }
}
