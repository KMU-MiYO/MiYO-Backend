package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Schema(description = "로그인 요청 DTO")
@Getter
@Setter
public class LoginRequest {

    @Schema(description = "사용자 아이디", example = "hong123", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "사용자 아이디는 필수입니다.")
    @Size(min = 3, max = 20, message = "사용자 아이디는 3자 이상 20자 이하여야 합니다.")
    private String userId;

    @Schema(description = "비밀번호", example = "password123!", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "비밀번호는 필수입니다.")
    @Size(min = 8, max = 100, message = "비밀번호는 8자 이상이어야 합니다.")
    private String password;
}
