package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Schema(description = "이메일 인증 요청 DTO")
@Getter
@NoArgsConstructor
public class EmailVerificationRequest {

    @Schema(description = "인증코드를 받을 이메일 주소", example = "hong@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;
}
