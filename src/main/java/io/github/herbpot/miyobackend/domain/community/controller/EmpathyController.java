package io.github.herbpot.miyobackend.domain.community.controller;

import io.github.herbpot.miyobackend.domain.community.service.EmpathyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * EmpathyController
 * - 공감 토글 API
 * - POST /v0/empathy: 공감 토글 (있으면 삭제, 없으면 추가)
 * - JWT 인증 필요
 */
@Slf4j
@RestController
@RequestMapping("/v0/empathy")
@RequiredArgsConstructor
public class EmpathyController {

    private final EmpathyService empathyService;

    /**
     * 공감 토글
     * - JWT에서 userId 추출
     * - Query Parameter로 postId 수신
     * - 공감이 없으면 추가, 있으면 삭제
     *
     * @param postId 게시글 ID
     * @param authentication Spring Security Authentication (JWT에서 추출한 userId 포함)
     * @return 공감 추가 여부 (true: 추가됨, false: 삭제됨)
     */
    @PostMapping
    public ResponseEntity<EmpathyToggleResponse> toggleEmpathy(
            @RequestParam Long postId,
            Authentication authentication) {

        // JWT에서 userId 추출
        String userId = (String) authentication.getPrincipal();

        log.info("POST /v0/empathy - userId={}, postId={}", userId, postId);

        boolean isAdded = empathyService.toggleEmpathy(userId, postId);

        log.info("POST /v0/empathy - Success: userId={}, postId={}, isAdded={}",
                userId, postId, isAdded);

        return ResponseEntity.ok(new EmpathyToggleResponse(
                isAdded,
                isAdded ? "공감이 추가되었습니다." : "공감이 삭제되었습니다."
        ));
    }

    /**
     * 공감 토글 응답 DTO
     */
    public record EmpathyToggleResponse(
            boolean isAdded,
            String message
    ) {
    }
}
