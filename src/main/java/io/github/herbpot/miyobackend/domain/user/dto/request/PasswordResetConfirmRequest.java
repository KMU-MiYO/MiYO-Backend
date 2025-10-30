package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Schema(description = "비밀번호 재설정 확인 요청 DTO")
@Getter
@NoArgsConstructor
public class PasswordResetConfirmRequest {

    @Schema(description = "새로운 비밀번호", example = "newPassword123!", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "새로운 비밀번호는 필수입니다.")
    @Size(min = 8, max = 100, message = "비밀번호는 8자 이상이어야 합니다.")
    private String newPassword;
}
