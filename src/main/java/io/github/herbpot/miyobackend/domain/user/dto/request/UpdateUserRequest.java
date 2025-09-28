package io.github.herbpot.miyobackend.domain.user.dto.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateUserRequest {

    private String nickname;
    private String profilePicture;
}
