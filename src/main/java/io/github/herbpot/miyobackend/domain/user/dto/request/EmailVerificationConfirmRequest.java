package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Schema(description = "이메일 인증 확인 요청 DTO")
@Getter
@NoArgsConstructor
public class EmailVerificationConfirmRequest {

    @Schema(description = "인증코드를 받은 이메일 주소", example = "hong@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;

    @Schema(description = "이메일로 받은 인증코드", example = "123456", requiredMode = Schema.RequiredMode.REQUIRED)
    private String code;
}
