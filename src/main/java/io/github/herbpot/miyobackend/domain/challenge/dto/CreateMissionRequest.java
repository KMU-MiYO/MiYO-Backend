package io.github.herbpot.miyobackend.domain.challenge.dto;

import io.github.herbpot.miyobackend.domain.challenge.entity.Mission;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

/**
 * CreateMissionRequest
 * - 관리자용 미션 생성 요청 DTO
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CreateMissionRequest {

    @NotBlank(message = "미션 제목은 필수입니다.")
    private String title;

    private String description;

    @NotNull(message = "목표 횟수는 필수입니다.")
    @Min(value = 1, message = "목표 횟수는 1 이상이어야 합니다.")
    private Integer goalCount;

    @NotBlank(message = "카테고리는 필수입니다.")
    private String category;

    @NotNull(message = "기간 타입은 필수입니다.")
    private Mission.PeriodType periodType;

    @NotNull(message = "시작일은 필수입니다.")
    private LocalDate startDate;

    @NotNull(message = "종료일은 필수입니다.")
    private LocalDate endDate;

    @NotNull(message = "보상 포인트는 필수입니다.")
    @Min(value = 0, message = "보상 포인트는 0 이상이어야 합니다.")
    private Integer rewardPoints;

    /**
     * DTO를 Mission 엔티티로 변환
     *
     * @return Mission 엔티티
     */
    public Mission toEntity() {
        return Mission.builder()
                .title(title)
                .description(description)
                .goalCount(goalCount)
                .category(category)
                .periodType(periodType)
                .startDate(startDate)
                .endDate(endDate)
                .rewardPoints(rewardPoints)
                .build();
    }
}
