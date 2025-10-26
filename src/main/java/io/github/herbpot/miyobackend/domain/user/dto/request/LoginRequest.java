package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Schema(description = "로그인 요청 DTO")
@Getter
@Setter
public class LoginRequest {

    @Schema(description = "사용자 아이디", example = "hong123", requiredMode = Schema.RequiredMode.REQUIRED)
    private String userId;

    @Schema(description = "비밀번호", example = "password123!", requiredMode = Schema.RequiredMode.REQUIRED)
    private String password;
}
