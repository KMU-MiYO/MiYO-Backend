package io.github.herbpot.miyobackend.domain.badge.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Schema(description = "뱃지 부여 요청 DTO")
@Getter
@Setter
public class AssignBadgeRequest {

    @Schema(description = "뱃지 ID", example = "1", requiredMode = Schema.RequiredMode.REQUIRED)
    private Long badgeId;
}
