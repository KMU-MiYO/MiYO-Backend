package io.github.herbpot.miyobackend.domain.badge.dto.response;

import io.github.herbpot.miyobackend.domain.badge.entity.UserBadge;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Schema(description = "사용자 뱃지 정보 응답 DTO")
@Getter
@Builder
public class UserBadgeResponse {

    @Schema(description = "뱃지 ID", example = "1")
    private final Long badgeId;

    @Schema(description = "뱃지 이름", example = "신규 가입자")
    private final String name;

    @Schema(description = "뱃지 설명", example = "처음 가입한 사용자에게 부여되는 뱃지입니다.")
    private final String description;

    @Schema(description = "뱃지 이미지 URL", example = "http://contest90-image-bucket.s3-website.kr.object.ncloudstorage.com/badges/welcome.png")
    private final String imageUrl;

    @Schema(description = "뱃지 획득 일시", example = "2025-01-15T10:30:00")
    private final LocalDateTime acquiredAt;

    public static UserBadgeResponse from(UserBadge userBadge) {
        return UserBadgeResponse.builder()
                .badgeId(userBadge.getBadge().getId())
                .name(userBadge.getBadge().getName())
                .description(userBadge.getBadge().getDescription())
                .imageUrl(userBadge.getBadge().getImageUrl())
                .acquiredAt(userBadge.getAcquiredAt())
                .build();
    }
}
