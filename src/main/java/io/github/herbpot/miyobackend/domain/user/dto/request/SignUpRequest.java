package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.github.herbpot.miyobackend.config.Authoriy;
import io.github.herbpot.miyobackend.domain.user.entity.User;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

@Schema(description = "회원 가입 요청 DTO")
@Getter
@Setter
public class SignUpRequest {

    @Schema(description = "닉네임", example = "홍길동", requiredMode = Schema.RequiredMode.REQUIRED)
    private String nickname;

    @Schema(description = "사용자 아이디 (중복 불가)", example = "hong123", requiredMode = Schema.RequiredMode.REQUIRED)
    private String userId;

    @Schema(description = "이메일 주소 (중복 불가)", example = "hong@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;

    @Schema(description = "비밀번호", example = "password123!", requiredMode = Schema.RequiredMode.REQUIRED)
    private String password;

    @Schema(description = "프로필 이미지 (선택사항)", type = "string", format = "binary")
    private MultipartFile profileImage;

    public User toEntity(String encodedPassword, String profilePicture) {
        return User.of(nickname, userId, email, encodedPassword, profilePicture, Authoriy.ROLE_USER);
    }
}
