package io.github.herbpot.miyobackend.domain.challenge.controller;

import io.github.herbpot.miyobackend.domain.challenge.dto.ContestCreateRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestResponse;
import io.github.herbpot.miyobackend.domain.challenge.dto.CreateMissionRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.MissionResponse;
import io.github.herbpot.miyobackend.domain.challenge.service.ContestService;
import io.github.herbpot.miyobackend.domain.challenge.service.MissionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
}
