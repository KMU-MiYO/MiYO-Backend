package io.github.herbpot.miyobackend.domain.badge.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

@Schema(description = "뱃지 생성 요청 DTO")
@Getter
@Setter
public class CreateBadgeRequest {

    @Schema(description = "뱃지 이름", example = "신규 가입자", requiredMode = Schema.RequiredMode.REQUIRED)
    private String name;

    @Schema(description = "뱃지 설명", example = "처음 가입한 사용자에게 부여되는 뱃지입니다.")
    private String description;

    @Schema(description = "뱃지 이미지", type = "string", format = "binary", requiredMode = Schema.RequiredMode.REQUIRED)
    private MultipartFile badgeImage;
}
