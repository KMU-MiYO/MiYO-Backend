package io.github.herbpot.miyobackend.domain.user.dto.response;

import io.github.herbpot.miyobackend.domain.user.entity.User;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Schema(description = "사용자 정보 응답 DTO")
@Getter
@Builder
public class UserInfoResponse {

    @Schema(description = "사용자 닉네임", example = "홍길동")
    private final String nickname;

    @Schema(description = "사용자 아이디", example = "hong123")
    private final String userId;

    @Schema(description = "사용자 이메일", example = "hong@example.com")
    private final String email;

    @Schema(description = "프로필 이미지 URL", example = "https://storage.example.com/profiles/hong123.jpg")
    private final String profilePicture;

    @Schema(description = "계정 생성 일시", example = "2025-01-15T10:30:00")
    private final LocalDateTime createdAt;

    public static UserInfoResponse from(User user) {
        return UserInfoResponse.builder()
                .nickname(user.getNickname())
                .userId(user.getUserId())
                .email(user.getEmail())
                .profilePicture(user.getProfilePicture())
                .createdAt(user.getCreatedAt())
                .build();
    }
}
