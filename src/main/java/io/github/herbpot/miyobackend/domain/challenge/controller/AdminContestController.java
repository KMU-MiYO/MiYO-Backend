package io.github.herbpot.miyobackend.domain.challenge.controller;

import io.github.herbpot.miyobackend.domain.challenge.dto.ContestCreateRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestResponse;
import io.github.herbpot.miyobackend.domain.challenge.dto.CreateMissionRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.MissionResponse;
import io.github.herbpot.miyobackend.domain.challenge.dto.UpdateUserMissionProgressRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.UserMissionProgressResponse;
import io.github.herbpot.miyobackend.domain.challenge.service.ContestService;
import io.github.herbpot.miyobackend.domain.challenge.service.MissionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * AdminContestController
 * - 관리자 전용 공모전 관리 API
 * - 공모전 생성, 삭제 등
 * - 인증 필요 (관리자 권한)
 */
@Slf4j
@RestController
@RequestMapping("/v0/adminMiYO")
@RequiredArgsConstructor
public class AdminContestController {

    private final ContestService contestService;
    private final MissionService missionService;

    /**
     * 공모전 생성
     *
     * @param request 공모전 생성 요청
     * @return 생성된 공모전 정보 (201 Created)
     */
    @PostMapping("/contests")
    public ResponseEntity<ContestResponse> createContest(@Valid @RequestBody ContestCreateRequest request) {
        log.info("POST /v0/adminMiYO/contests - Creating contest: title={}", request.getTitle());

        ContestResponse response = contestService.createContest(request);

        log.info("Contest created successfully: contestId={}", response.getContestId());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 공모전 삭제
     *
     * @param contestId 삭제할 공모전 ID
     * @return 204 No Content
     */
    @DeleteMapping("/contests/{contestId}")
    public ResponseEntity<Void> deleteContest(@PathVariable Long contestId) {
        log.info("DELETE /v0/adminMiYO/contests/{} - Deleting contest", contestId);

        contestService.deleteContest(contestId);

        log.info("Contest deleted successfully: contestId={}", contestId);
        return ResponseEntity.noContent().build();
    }

    /**
     * 미션 생성
     *
     * @param request 미션 생성 요청
     * @return 생성된 미션 정보 (201 Created)
     */
    @PostMapping("/missions")
    public ResponseEntity<MissionResponse> createMission(@Valid @RequestBody CreateMissionRequest request) {
        log.info("POST /v0/adminMiYO/missions - Creating mission: title={}, category={}",
                request.getTitle(), request.getCategory());

        MissionResponse response = missionService.createMission(request);

        log.info("Mission created successfully: missionId={}", response.getMissionId());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 미션 삭제
     *
     * @param missionId 삭제할 미션 ID
     * @return 204 No Content
     */
    @DeleteMapping("/missions/{missionId}")
    public ResponseEntity<Void> deleteMission(@PathVariable Long missionId) {
        log.info("DELETE /v0/adminMiYO/missions/{} - Deleting mission", missionId);

        missionService.deleteMission(missionId);

        log.info("Mission deleted successfully: missionId={}", missionId);
        return ResponseEntity.noContent().build();
    }

    /**
     * 특정 유저의 미션 진행도 조회
     *
     * @param userId 사용자 ID
     * @return 미션 진행도 목록
     */
    @GetMapping("/users/{userId}/missions")
    public ResponseEntity<List<UserMissionProgressResponse>> getUserMissions(@PathVariable String userId) {
        log.info("GET /v0/adminMiYO/users/{}/missions - Getting user missions", userId);

        List<UserMissionProgressResponse> missions = missionService.getUserMissionsForAdmin(userId);

        log.info("Retrieved {} missions for user: userId={}", missions.size(), userId);
        return ResponseEntity.ok(missions);
    }

    /**
     * 특정 유저의 특정 미션 진행도 수정
     *
     * @param userId 사용자 ID
     * @param missionId 미션 ID
     * @param request 진행도 수정 요청
     * @return 수정된 진행도 정보
     */
    @PutMapping("/users/{userId}/missions/{missionId}")
    public ResponseEntity<UserMissionProgressResponse> updateUserMissionProgress(
            @PathVariable String userId,
            @PathVariable Long missionId,
            @Valid @RequestBody UpdateUserMissionProgressRequest request) {
        log.info("PUT /v0/adminMiYO/users/{}/missions/{} - Updating user mission progress", userId, missionId);

        UserMissionProgressResponse response = missionService.updateUserMissionProgress(userId, missionId, request);

        log.info("User mission progress updated successfully: userId={}, missionId={}", userId, missionId);
        return ResponseEntity.ok(response);
    }

    /**
     * 특정 유저의 특정 미션 진행도 초기화
     *
     * @param userId 사용자 ID
     * @param missionId 미션 ID
     * @return 204 No Content
     */
    @PatchMapping("/users/{userId}/missions/{missionId}/reset")
    public ResponseEntity<Void> resetUserMissionProgress(
            @PathVariable String userId,
            @PathVariable Long missionId) {
        log.info("PATCH /v0/adminMiYO/users/{}/missions/{}/reset - Resetting user mission progress", userId, missionId);

        missionService.resetUserMissionProgress(userId, missionId);

        log.info("User mission progress reset successfully: userId={}, missionId={}", userId, missionId);
        return ResponseEntity.noContent().build();
    }

    /**
     * 특정 유저의 특정 미션 진행도 삭제
     *
     * @param userId 사용자 ID
     * @param missionId 미션 ID
     * @return 204 No Content
     */
    @DeleteMapping("/users/{userId}/missions/{missionId}")
    public ResponseEntity<Void> deleteUserMissionProgress(
            @PathVariable String userId,
            @PathVariable Long missionId) {
        log.info("DELETE /v0/adminMiYO/users/{}/missions/{} - Deleting user mission progress", userId, missionId);

        missionService.deleteUserMissionProgress(userId, missionId);

        log.info("User mission progress deleted successfully: userId={}, missionId={}", userId, missionId);
        return ResponseEntity.noContent().build();
    }
}
