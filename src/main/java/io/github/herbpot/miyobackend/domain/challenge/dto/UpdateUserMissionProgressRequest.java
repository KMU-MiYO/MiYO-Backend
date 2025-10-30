package io.github.herbpot.miyobackend.domain.challenge.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * UpdateUserMissionProgressRequest
 * - 관리자용 유저 미션 진행도 수정 요청 DTO
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUserMissionProgressRequest {

    @NotNull(message = "현재 진행도는 필수입니다.")
    @Min(value = 0, message = "현재 진행도는 0 이상이어야 합니다.")
    private Integer currentCount;

    @NotNull(message = "완료 여부는 필수입니다.")
    private Boolean completed;
}
