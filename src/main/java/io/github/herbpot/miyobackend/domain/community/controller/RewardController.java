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

    @PutMapping("/update/{userId}")
    public ResponseEntity<RewardDTO> updateReward(@PathVariable("userId") String userId, @RequestParam("v") Integer v) {
        if (!rewardRepository.existsByUserId(userId)) {
            RewardModel savedModel = rewardRepository.save(
                    RewardModel.builder()
                            .userId(userId)
                            .reward(v)
                            .build()
            );
            return ResponseEntity.ok(RewardDTO.from(savedModel));
        }
        else {
            rewardRepository.updateReward(userId, v);
            // 업데이트 후 최신 정보 조회
            RewardModel updatedModel = rewardRepository.findByUserId(userId)
                    .orElseThrow(() -> new IllegalArgumentException("리워드 정보를 찾을 수 없습니다."));
            return ResponseEntity.ok(RewardDTO.from(updatedModel));
        }
    }

    @PostMapping("/insert")
    public ResponseEntity<RewardDTO> insertReward(@RequestBody RewardModel rewardModel) {
        RewardModel savedModel = rewardRepository.save(rewardModel);
        return ResponseEntity.ok(RewardDTO.from(savedModel));
    }
}
