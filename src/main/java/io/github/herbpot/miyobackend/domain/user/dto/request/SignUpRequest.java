package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.github.herbpot.miyobackend.domain.user.entity.User;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignUpRequest {

    private String nickname;
    private String userId;
    private String email;
    private String password;
    private String profilePicture;

    public User toEntity(String encodedPassword) {
        return User.of(nickname, userId, email, encodedPassword, profilePicture);
    }
}
