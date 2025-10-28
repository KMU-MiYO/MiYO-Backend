package io.github.herbpot.miyobackend.domain.challenge.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

/**
 * ContestCreateRequest
 * - 관리자용 공모전 생성 요청 DTO
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ContestCreateRequest {

    @NotBlank(message = "공모전 제목은 필수입니다.")
    private String title;

    private String host;

    private String description;

    @NotNull(message = "시작일은 필수입니다.")
    private LocalDate startDate;

    @NotNull(message = "종료일은 필수입니다.")
    private LocalDate endDate;

    private Integer reward1st;

    private Integer reward2nd;

    private Integer reward3rd;

    private String rewardDescription;

    private String thumbnailUrl;
}
