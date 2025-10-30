package io.github.herbpot.miyobackend.domain.community.dto;

import io.github.herbpot.miyobackend.domain.community.entity.write.RewardModel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RewardDTO {

    private String userId;

    private Integer reward;

    public static RewardDTO from(RewardModel rewardModel) {
        return RewardDTO.builder()
                .userId(rewardModel.getUserId())
                .reward(rewardModel.getReward())
                .build();
    }
}
