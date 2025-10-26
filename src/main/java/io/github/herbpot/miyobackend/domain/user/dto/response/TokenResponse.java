package io.github.herbpot.miyobackend.domain.user.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Schema(description = "JWT 토큰 응답 DTO")
@Getter
@AllArgsConstructor
public class TokenResponse {

    @Schema(
            description = "JWT 액세스 토큰 (API 요청 시 Authorization 헤더에 'Bearer {token}' 형식으로 포함)",
            example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJob25nMTIzIiwiaWF0IjoxNjQwOTk1MjAwLCJleHAiOjE2NDA5OTg4MDB9.abcdef123456"
    )
    private final String accessToken;
}
