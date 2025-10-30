package io.github.herbpot.miyobackend.domain.community.controller;

import io.github.herbpot.miyobackend.domain.community.dto.RewardDTO;
import io.github.herbpot.miyobackend.domain.community.entity.write.RewardModel;
import io.github.herbpot.miyobackend.domain.community.repository.write.RewardRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Tag(name = "리워드", description = "사용자 리워드 관리 API")
@Slf4j
@RestController
@RequestMapping("/v0/reward")
@RequiredArgsConstructor
public class RewardController {

    private final RewardRepository rewardRepository;

    @Operation(
            summary = "리워드 업데이트",
            description = "사용자의 리워드 점수를 업데이트합니다. 사용자가 없으면 새로 생성합니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "리워드 업데이트 성공",
                    content = @Content(schema = @Schema(implementation = RewardDTO.class))
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청")
    })
    @PutMapping("/update/{userId}")
    public ResponseEntity<RewardDTO> updateReward(
            @Parameter(description = "사용자 ID", example = "user123", required = true)
            @PathVariable("userId") String userId,
            @Parameter(description = "리워드 점수", example = "100", required = true)
            @RequestParam("v") Integer v) {
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

    @Operation(
            summary = "리워드 추가",
            description = "새로운 리워드 정보를 추가합니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "리워드 추가 성공",
                    content = @Content(schema = @Schema(implementation = RewardDTO.class))
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청")
    })
    @PostMapping("/insert")
    public ResponseEntity<RewardDTO> insertReward(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "리워드 정보",
                    required = true,
                    content = @Content(schema = @Schema(implementation = RewardDTO.class))
            )
            @RequestBody RewardDTO rewardDTO) {
        // DTO로 받아서 새로운 엔티티 생성 (id 없이)
        RewardModel newReward = RewardModel.builder()
                .userId(rewardDTO.getUserId())
                .reward(rewardDTO.getReward())
                .build();

        RewardModel savedModel = rewardRepository.save(newReward);
        return ResponseEntity.ok(RewardDTO.from(savedModel));
    }

    @Operation(
            summary = "리워드 조회",
            description = "사용자의 리워드 정보를 조회합니다. 리워드가 없으면 0으로 반환됩니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "리워드 조회 성공",
                    content = @Content(schema = @Schema(implementation = RewardDTO.class))
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청")
    })
    @GetMapping("/my")
    public ResponseEntity<RewardDTO> getReward(
            @Parameter(description = "사용자 ID", example = "user123", required = true)
            @RequestParam("userId") String userId) {
        log.info("GET /v0/reward/my - Getting reward for user: userId={}", userId);

        // 유저의 리워드 조회, 없으면 0으로 초기화된 DTO 반환
        RewardModel rewardModel = rewardRepository.findByUserId(userId)
                .orElse(RewardModel.builder()
                        .userId(userId)
                        .reward(0)
                        .build());

        log.info("Reward retrieved: userId={}, reward={}", userId, rewardModel.getReward());
        return ResponseEntity.ok(RewardDTO.from(rewardModel));
    }
}
