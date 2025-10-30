package io.github.herbpot.miyobackend.domain.challenge.controller;

import io.github.herbpot.miyobackend.domain.challenge.dto.MissionResponse;
import io.github.herbpot.miyobackend.domain.challenge.dto.UserMissionProgressResponse;
import io.github.herbpot.miyobackend.domain.challenge.entity.Mission;
import io.github.herbpot.miyobackend.domain.challenge.service.MissionService;
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
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * MissionController
 * - 미션 관련 API
 * - 개인별 미션 조회, 진행 현황 조회
 * - JWT 인증 필요
 */
@Tag(name = "미션 API", description = "사용자 미션 조회 및 진행 현황 관리 API")
@Slf4j
@RestController
@RequestMapping("/v0/missions")
@RequiredArgsConstructor
public class MissionController {

    private final MissionService missionService;

    /**
     * 내 미션 목록 조회 (진행 현황 포함)
     * - 사용자에게 자동으로 할당된 미션 목록
     * - 각 미션의 진행 현황 포함
     *
     * @param authentication Spring Security Authentication
     * @return 미션 목록 (진행 현황 포함) (200 OK)
     */
    @Operation(
            summary = "내 미션 목록 조회",
            description = """
                    현재 사용자에게 할당된 모든 미션 목록을 조회합니다.

                    - 각 미션의 진행 현황 포함
                    - 완료 여부 및 진행률 제공
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = MissionResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @GetMapping
    public ResponseEntity<List<MissionResponse>> getMyMissions(
            @Parameter(hidden = true) Authentication authentication) {
        String userId = (String) authentication.getPrincipal();
        log.info("GET /v0/missions - Getting user missions: userId={}", userId);

        List<MissionResponse> missions = missionService.getUserMissions(userId);
        return ResponseEntity.ok(missions);
    }

    /**
     * 완료된 미션 목록 조회
     *
     * @param authentication Spring Security Authentication
     * @return 완료된 미션 목록 (200 OK)
     */
    @Operation(
            summary = "완료된 미션 목록 조회",
            description = """
                    현재 사용자가 완료한 미션 목록을 조회합니다.

                    - 완료된 미션만 필터링하여 반환
                    - 완료 시간 및 상세 정보 포함
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = UserMissionProgressResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @GetMapping("/completed")
    public ResponseEntity<List<UserMissionProgressResponse>> getCompletedMissions(
            @Parameter(hidden = true) Authentication authentication) {
        String userId = (String) authentication.getPrincipal();
        log.info("GET /v0/missions/completed - Getting completed missions: userId={}", userId);

        List<UserMissionProgressResponse> completedMissions = missionService.getCompletedMissions(userId);
        return ResponseEntity.ok(completedMissions);
    }
}
