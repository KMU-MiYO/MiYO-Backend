package io.github.herbpot.miyobackend.domain.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ExistsResponse {
    private final boolean exists;
}
