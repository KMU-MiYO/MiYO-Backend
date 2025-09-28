package io.github.herbpot.miyobackend.domain.user.dto.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest {

    private String userId;
    private String password;
}
