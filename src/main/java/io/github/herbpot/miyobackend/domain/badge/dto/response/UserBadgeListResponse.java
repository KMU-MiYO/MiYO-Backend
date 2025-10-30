package io.github.herbpot.miyobackend.domain.badge.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Schema(description = "사용자 뱃지 목록 응답 DTO")
@Getter
@Builder
public class UserBadgeListResponse {

    @Schema(description = "총 뱃지 개수", example = "3")
    private final Long totalCount;

    @Schema(description = "뱃지 목록")
    private final List<UserBadgeResponse> badges;

    public static UserBadgeListResponse of(Long totalCount, List<UserBadgeResponse> badges) {
        return UserBadgeListResponse.builder()
                .totalCount(totalCount)
                .badges(badges)
                .build();
    }
}
