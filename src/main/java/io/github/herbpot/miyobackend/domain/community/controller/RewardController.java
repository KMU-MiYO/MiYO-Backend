package io.github.herbpot.miyobackend.domain.community.controller;

import io.github.herbpot.miyobackend.domain.community.dto.RewardDTO;
import io.github.herbpot.miyobackend.domain.community.entity.write.RewardModel;
import io.github.herbpot.miyobackend.domain.community.repository.write.RewardRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/v0/reward")
@RequiredArgsConstructor
public class RewardController {

    private final RewardRepository rewardRepository;

    @GetMapping("/update/{userId}")
    public ResponseEntity<RewardDTO> updateReward(@PathVariable("userId") String userId, @RequestParam("v") Integer v) {
        if (rewardRepository.existsByUserId(userId)) {
            return ResponseEntity.ok(RewardDTO.from(rewardRepository.insert(
                    RewardModel.builder()
                            .userId(userId)
                            .reward(v)
                            .build()
            ).get()));
        }
        else
            return ResponseEntity.ok(RewardDTO.from(rewardRepository.updateReward(userId, v).get()));
    }

    @PostMapping("/insert")
    public ResponseEntity<RewardDTO> insertReward(@RequestBody RewardModel rewardModel) {
        rewardRepository.insert(rewardModel);
        return ResponseEntity.ok(RewardDTO.from(rewardModel));
    }
}
