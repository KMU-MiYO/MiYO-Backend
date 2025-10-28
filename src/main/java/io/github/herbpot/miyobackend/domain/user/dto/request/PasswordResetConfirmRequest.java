package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Schema(description = "비밀번호 재설정 확인 요청 DTO")
@Getter
@NoArgsConstructor
public class PasswordResetConfirmRequest {

    @Schema(description = "새로운 비밀번호", example = "newPassword123!", requiredMode = Schema.RequiredMode.REQUIRED)
    private String newPassword;
}
