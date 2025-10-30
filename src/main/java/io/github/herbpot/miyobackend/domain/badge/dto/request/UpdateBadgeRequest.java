package io.github.herbpot.miyobackend.domain.badge.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

@Schema(description = "뱃지 수정 요청 DTO")
@Getter
@Setter
public class UpdateBadgeRequest {

    @Schema(description = "뱃지 이름", example = "신규 가입자")
    private String name;

    @Schema(description = "뱃지 설명", example = "처음 가입한 사용자에게 부여되는 뱃지입니다.")
    private String description;

    @Schema(description = "뱃지 이미지 (선택사항)", type = "string", format = "binary")
    private MultipartFile badgeImage;
}
