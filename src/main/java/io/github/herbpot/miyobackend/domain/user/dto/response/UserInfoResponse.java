package io.github.herbpot.miyobackend.domain.user.dto.response;

import io.github.herbpot.miyobackend.domain.user.entity.User;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class UserInfoResponse {

    private final String nickname;
    private final String userId;
    private final String email;
    private final String profilePicture;
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
