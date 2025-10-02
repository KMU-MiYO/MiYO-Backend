package io.github.herbpot.miyobackend.domain.user.dto.request;

import lombok.Getter;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

@Getter
@Setter
public class UpdateUserRequest {

    private String nickname;
    private MultipartFile profileImage;
}
