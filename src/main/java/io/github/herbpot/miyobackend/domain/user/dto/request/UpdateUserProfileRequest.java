package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

@Schema(description = "사용자 정보 수정 요청 DTO")
@Getter
@Setter
public class UpdateUserProfileRequest {

    @Schema(description = "변경할 프로필 이미지 (선택사항)", type = "string", format = "binary")
    private MultipartFile profileImage;
}
