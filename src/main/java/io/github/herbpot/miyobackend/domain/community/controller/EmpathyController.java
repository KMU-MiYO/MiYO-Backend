package io.github.herbpot.miyobackend.domain.community.controller;

import io.github.herbpot.miyobackend.domain.community.service.EmpathyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "공감", description = "게시글 공감 토글 API")
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
    @Operation(
            summary = "공감 토글",
            description = "게시글에 공감을 토글합니다. 공감이 없으면 추가하고, 있으면 삭제합니다.",
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "공감 토글 성공",
                    content = @Content(schema = @Schema(implementation = EmpathyToggleResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패 (JWT 토큰 없음 또는 만료)"),
            @ApiResponse(responseCode = "404", description = "게시글을 찾을 수 없습니다")
    })
    @PostMapping
    public ResponseEntity<EmpathyToggleResponse> toggleEmpathy(
            @Parameter(description = "게시글 ID", example = "1", required = true)
            @RequestParam Long postId,
            @Parameter(hidden = true) Authentication authentication) {

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
