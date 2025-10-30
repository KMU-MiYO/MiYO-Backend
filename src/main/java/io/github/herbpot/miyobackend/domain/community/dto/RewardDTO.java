package io.github.herbpot.miyobackend.domain.community.dto;

import io.github.herbpot.miyobackend.domain.community.entity.write.RewardModel;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Schema(description = "리워드 정보")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RewardDTO {

    @Schema(description = "사용자 ID", example = "user123")
    private String userId;

    @Schema(description = "리워드 점수", example = "100")
    private Integer reward;

    public static RewardDTO from(RewardModel rewardModel) {
        return RewardDTO.builder()
                .userId(rewardModel.getUserId())
                .reward(rewardModel.getReward())
                .build();
    }
}
