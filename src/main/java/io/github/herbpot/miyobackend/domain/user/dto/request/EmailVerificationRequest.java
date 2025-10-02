package io.github.herbpot.miyobackend.domain.user.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class EmailVerificationRequest {
    private String email;
}
