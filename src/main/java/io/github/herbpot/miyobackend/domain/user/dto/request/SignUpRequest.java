package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.github.herbpot.miyobackend.config.Authoriy;
import io.github.herbpot.miyobackend.domain.user.entity.User;
import lombok.Getter;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

@Getter
@Setter
public class SignUpRequest {

    private String nickname;
    private String userId;
    private String email;
    private String password;
    private MultipartFile profileImage;

    public User toEntity(String encodedPassword, String profilePicture) {
        return User.of(nickname, userId, email, encodedPassword, profilePicture, Authoriy.ROLE_USER);
    }
}
