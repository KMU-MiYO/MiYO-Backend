package io.github.herbpot.miyobackend.domain.challenge.controller;

import io.github.herbpot.miyobackend.domain.challenge.dto.MissionResponse;
import io.github.herbpot.miyobackend.domain.challenge.dto.UserMissionProgressResponse;
import io.github.herbpot.miyobackend.domain.challenge.entity.Mission;
import io.github.herbpot.miyobackend.domain.challenge.service.MissionService;
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
    @GetMapping
    public ResponseEntity<List<MissionResponse>> getMyMissions(Authentication authentication) {
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
    @GetMapping("/completed")
    public ResponseEntity<List<UserMissionProgressResponse>> getCompletedMissions(Authentication authentication) {
        String userId = (String) authentication.getPrincipal();
        log.info("GET /v0/missions/completed - Getting completed missions: userId={}", userId);

        List<UserMissionProgressResponse> completedMissions = missionService.getCompletedMissions(userId);
        return ResponseEntity.ok(completedMissions);
    }
}
