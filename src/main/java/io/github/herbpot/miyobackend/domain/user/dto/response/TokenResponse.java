package io.github.herbpot.miyobackend.domain.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TokenResponse {

    private final String accessToken;
}
