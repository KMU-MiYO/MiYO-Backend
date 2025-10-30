package io.github.herbpot.miyobackend.domain.challenge.controller;

import io.github.herbpot.miyobackend.domain.challenge.dto.ContestCreateRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestResponse;
import io.github.herbpot.miyobackend.domain.challenge.dto.CreateMissionRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.MissionResponse;
import io.github.herbpot.miyobackend.domain.challenge.dto.UpdateUserMissionProgressRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.UserMissionProgressResponse;
import io.github.herbpot.miyobackend.domain.challenge.service.ContestService;
import io.github.herbpot.miyobackend.domain.challenge.service.MissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "관리자 API", description = "공모전 및 미션 관리를 위한 관리자 전용 API")
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
    @Operation(
            summary = "공모전 생성",
            description = "새로운 공모전을 생성합니다. 관리자 권한이 필요합니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "공모전 생성 성공",
                    content = @Content(schema = @Schema(implementation = ContestResponse.class))
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청 데이터"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
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
    @Operation(
            summary = "공모전 삭제",
            description = "기존 공모전을 삭제합니다. 관리자 권한이 필요합니다."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "공모전 삭제 성공"),
            @ApiResponse(responseCode = "404", description = "공모전을 찾을 수 없음"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @DeleteMapping("/contests/{contestId}")
    public ResponseEntity<Void> deleteContest(
            @Parameter(description = "삭제할 공모전 ID", required = true)
            @PathVariable Long contestId) {
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
    @Operation(
            summary = "미션 생성",
            description = "새로운 미션을 생성합니다. 관리자 권한이 필요합니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "미션 생성 성공",
                    content = @Content(schema = @Schema(implementation = MissionResponse.class))
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청 데이터"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
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
    @Operation(
            summary = "미션 삭제",
            description = "기존 미션을 삭제합니다. 관리자 권한이 필요합니다."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "미션 삭제 성공"),
            @ApiResponse(responseCode = "404", description = "미션을 찾을 수 없음"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @DeleteMapping("/missions/{missionId}")
    public ResponseEntity<Void> deleteMission(
            @Parameter(description = "삭제할 미션 ID", required = true)
            @PathVariable Long missionId) {
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
    @Operation(
            summary = "사용자의 미션 진행도 조회",
            description = "특정 사용자의 모든 미션 진행도를 조회합니다. 관리자 권한이 필요합니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = UserMissionProgressResponse.class))
            ),
            @ApiResponse(responseCode = "404", description = "사용자를 찾을 수 없음"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @GetMapping("/users/{userId}/missions")
    public ResponseEntity<List<UserMissionProgressResponse>> getUserMissions(
            @Parameter(description = "사용자 ID", required = true)
            @PathVariable String userId) {
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
    @Operation(
            summary = "사용자 미션 진행도 수정",
            description = "특정 사용자의 특정 미션 진행도를 수정합니다. 관리자 권한이 필요합니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "수정 성공",
                    content = @Content(schema = @Schema(implementation = UserMissionProgressResponse.class))
            ),
            @ApiResponse(responseCode = "404", description = "사용자 또는 미션을 찾을 수 없음"),
            @ApiResponse(responseCode = "400", description = "잘못된 요청 데이터"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @PutMapping("/users/{userId}/missions/{missionId}")
    public ResponseEntity<UserMissionProgressResponse> updateUserMissionProgress(
            @Parameter(description = "사용자 ID", required = true)
            @PathVariable String userId,
            @Parameter(description = "미션 ID", required = true)
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
    @Operation(
            summary = "사용자 미션 진행도 초기화",
            description = "특정 사용자의 특정 미션 진행도를 초기화합니다. 관리자 권한이 필요합니다."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "초기화 성공"),
            @ApiResponse(responseCode = "404", description = "사용자 또는 미션을 찾을 수 없음"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @PatchMapping("/users/{userId}/missions/{missionId}/reset")
    public ResponseEntity<Void> resetUserMissionProgress(
            @Parameter(description = "사용자 ID", required = true)
            @PathVariable String userId,
            @Parameter(description = "미션 ID", required = true)
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
    @Operation(
            summary = "사용자 미션 진행도 삭제",
            description = "특정 사용자의 특정 미션 진행도를 삭제합니다. 관리자 권한이 필요합니다."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "삭제 성공"),
            @ApiResponse(responseCode = "404", description = "사용자 또는 미션을 찾을 수 없음"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @DeleteMapping("/users/{userId}/missions/{missionId}")
    public ResponseEntity<Void> deleteUserMissionProgress(
            @Parameter(description = "사용자 ID", required = true)
            @PathVariable String userId,
            @Parameter(description = "미션 ID", required = true)
            @PathVariable Long missionId) {
        log.info("DELETE /v0/adminMiYO/users/{}/missions/{} - Deleting user mission progress", userId, missionId);

        missionService.deleteUserMissionProgress(userId, missionId);

        log.info("User mission progress deleted successfully: userId={}, missionId={}", userId, missionId);
        return ResponseEntity.noContent().build();
    }
}
