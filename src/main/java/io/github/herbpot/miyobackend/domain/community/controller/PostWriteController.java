package io.github.herbpot.miyobackend.domain.community.controller;

import io.github.herbpot.miyobackend.domain.community.dto.PostCreateRequest;
import io.github.herbpot.miyobackend.domain.community.dto.PostResponse;
import io.github.herbpot.miyobackend.domain.community.service.PostWriteService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * PostWriteController
 * - 게시글 쓰기 작업 API (CQRS Write)
 * - POST /v0/posts: 게시글 작성
 * - DELETE /v0/posts: 게시글 삭제
 * - JWT 인증 필요
 */
@Tag(name = "게시글 작성/삭제", description = "게시글 작성 및 삭제 API (CQRS Write)")
@Slf4j
@RestController
@RequestMapping("/v0/posts")
@RequiredArgsConstructor
public class PostWriteController {

    private final PostWriteService postWriteService;

    /**
     * 게시글 작성
     * - JWT에서 userId 추출하여 사용
     * - Request Body를 통해 게시글 정보 수신
     * - Validation 수행 (@Valid)
     * - Write DB에 저장 후 Redis 이벤트 발행
     * - 201 Created 응답
     *
     * @param request 게시글 작성 요청
     * @param authentication Spring Security Authentication (JWT에서 추출한 userId 포함)
     * @return 생성된 게시글 정보 (201 Created)
     */
    @Operation(
            summary = "게시글 작성",
            description = "새로운 게시글을 작성합니다. JWT 토큰이 필요하며, 사용자 ID는 토큰에서 추출됩니다.",
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "게시글이 성공적으로 작성되었습니다",
                    content = @Content(schema = @Schema(implementation = PostResponse.class))
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청 (Validation 실패)"),
            @ApiResponse(responseCode = "401", description = "인증 실패 (JWT 토큰 없음 또는 만료)")
    })
    @PostMapping
    public ResponseEntity<PostResponse> createPost(
            @Valid @RequestBody PostCreateRequest request,
            @Parameter(hidden = true) Authentication authentication,
            @Parameter(hidden = true) @RequestHeader("Authorization") String token) {

        // JWT에서 userId 추출
        String userId = (String) authentication.getPrincipal();

        log.info("POST /v0/posts - Creating post: userId={}", userId);

        PostResponse response = postWriteService.createPost(request, userId, token);

        log.info("POST /v0/posts - Post created: postId={}", response.getPostId());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 게시글 삭제 (하드 삭제)
     * - JWT에서 userId 추출하여 본인 확인
     * - Query Parameter로 postId 수신
     * - 본인이 작성한 게시글만 삭제 가능
     * - Write DB에서 삭제 후 Redis 이벤트 발행
     * - 204 No Content 응답
     *
     * @param postId 삭제할 게시글 ID
     * @param authentication Spring Security Authentication (JWT에서 추출한 userId 포함)
     * @return 204 No Content
     * @throws IllegalArgumentException 게시글이 존재하지 않거나 권한이 없는 경우 (400 Bad Request로 변환됨)
     */
    @Operation(
            summary = "게시글 삭제",
            description = "게시글을 삭제합니다. 본인이 작성한 게시글만 삭제 가능합니다.",
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "게시글이 성공적으로 삭제되었습니다"),
            @ApiResponse(responseCode = "400", description = "게시글이 존재하지 않거나 권한이 없습니다"),
            @ApiResponse(responseCode = "401", description = "인증 실패 (JWT 토큰 없음 또는 만료)")
    })
    @DeleteMapping
    public ResponseEntity<Void> deletePost(
            @Parameter(description = "삭제할 게시글 ID", example = "1", required = true)
            @RequestParam Long postId,
            @Parameter(hidden = true) Authentication authentication) {

        // JWT에서 userId 추출
        String userId = (String) authentication.getPrincipal();

        log.info("DELETE /v0/posts - Deleting post: postId={}, userId={}", postId, userId);

        postWriteService.deletePost(postId, userId);

        log.info("DELETE /v0/posts - Post deleted: postId={}", postId);

        return ResponseEntity.noContent().build();
    }

    /**
     * 예외 처리: IllegalArgumentException
     * - 게시글이 존재하지 않거나 권한이 없는 경우
     * - 400 Bad Request 응답
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException e) {
        log.warn("IllegalArgumentException: {}", e.getMessage());
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(e.getMessage()));
    }

    /**
     * 에러 응답 DTO
     */
    public record ErrorResponse(String message) {
    }
}
