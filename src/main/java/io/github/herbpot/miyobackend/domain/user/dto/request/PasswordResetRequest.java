package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Schema(description = "비밀번호 재설정 요청 DTO")
@Getter
@NoArgsConstructor
public class PasswordResetRequest {

    @Schema(description = "가입 시 사용한 이메일 주소", example = "hong@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;
}
