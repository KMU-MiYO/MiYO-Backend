package io.github.herbpot.miyobackend.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Schema(description = "사용자 정보 수정 요청 DTO")
@Getter
@Setter
public class UpdateUserNickNameRequest {

    @Schema(description = "변경할 닉네임 (선택사항)", example = "새로운닉네임")
    private String nickname;
}
