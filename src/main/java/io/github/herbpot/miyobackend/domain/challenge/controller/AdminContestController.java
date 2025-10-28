package io.github.herbpot.miyobackend.domain.challenge.controller;

import io.github.herbpot.miyobackend.domain.challenge.dto.ContestCreateRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestResponse;
import io.github.herbpot.miyobackend.domain.challenge.service.ContestService;
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
@RequestMapping("/v0/contests/adminMiYO")
@RequiredArgsConstructor
public class AdminContestController {

    private final ContestService contestService;

    /**
     * 공모전 생성
     *
     * @param request 공모전 생성 요청
     * @return 생성된 공모전 정보 (201 Created)
     */
    @PostMapping
    public ResponseEntity<ContestResponse> createContest(@Valid @RequestBody ContestCreateRequest request) {
        log.info("POST /v0/contests/adminMiYO - Creating contest: title={}", request.getTitle());

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
    @DeleteMapping("/{contestId}")
    public ResponseEntity<Void> deleteContest(@PathVariable Long contestId) {
        log.info("DELETE /v0/contests/adminMiYO/{} - Deleting contest", contestId);

        contestService.deleteContest(contestId);

        log.info("Contest deleted successfully: contestId={}", contestId);
        return ResponseEntity.noContent().build();
    }
}
