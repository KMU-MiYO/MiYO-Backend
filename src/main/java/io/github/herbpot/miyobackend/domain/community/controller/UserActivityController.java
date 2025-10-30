package io.github.herbpot.miyobackend.domain.community.controller;

import io.github.herbpot.miyobackend.domain.community.dto.PageResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PostListResponse;
import io.github.herbpot.miyobackend.domain.community.dto.UserActivityCountResponse;
import io.github.herbpot.miyobackend.domain.community.service.UserActivityService;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * UserActivityController
 * - 사용자의 활동 내역 조회 API
 * - GET /v0/users/posts/count: 사용자가 작성한 게시글 개수 조회
 * - GET /v0/users/posts: 사용자가 작성한 게시글 목록 조회
 * - GET /v0/users/comments/count: 사용자가 작성한 댓글 개수 조회
 * - GET /v0/users/comments: 사용자가 작성한 댓글 목록 조회
 * - GET /v0/users/empathy/count: 사용자가 공감한 게시글 개수 조회
 * - GET /v0/users/empathy: 사용자가 공감한 게시글 목록 조회
 * - JWT 인증 필수
 */
@Tag(name = "사용자 활동", description = "사용자의 게시글, 댓글, 공감 활동 조회 API")
@Slf4j
@RestController
@RequestMapping("/v0/users/posts")
@RequiredArgsConstructor
public class UserActivityController {

    private final UserActivityService userActivityService;

    /**
     * 사용자가 작성한 게시글 개수 조회
     * - JWT에서 userId 추출 (인증 필수)
     * - 해당 사용자가 작성한 게시글 개수 반환 (댓글 제외)
     * - categories로 여러 카테고리 필터링 (optional)
     *
     * @param categories 카테고리 리스트 (optional, 예: NATURE, CULTURE, TRAFFIC, RESIDENCE, COMMERCIAL, NIGHT, ENVIRONMENT)
     * @param authentication Spring Security Authentication (JWT에서 추출, 필수)
     * @return 사용자의 게시글 개수
     */
    @Operation(
            summary = "내 게시글 개수 조회",
            description = "로그인한 사용자가 작성한 게시글 개수를 조회합니다.",
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "게시글 개수 조회 성공",
                    content = @Content(schema = @Schema(implementation = UserActivityCountResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @GetMapping("/posts/count")
    public ResponseEntity<UserActivityCountResponse> getUserPostsCount(
            @Parameter(description = "카테고리 리스트", example = "[\"NATURE\", \"CULTURE\"]")
            @RequestParam(required = false) java.util.List<String> categories,
            @Parameter(hidden = true) Authentication authentication) {

        // JWT에서 userId 추출 (인증 필수)
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("인증이 필요한 API입니다.");
        }
        String userId = (String) authentication.getPrincipal();

        log.info("GET /v0/users/posts/count - Getting user posts count: userId={}, categories={}",
                userId, categories);

        // 서비스 호출
        long count = userActivityService.getUserPostsCount(userId, categories);

        log.info("GET /v0/users/posts/count - User posts count: userId={}, count={}", userId, count);

        return ResponseEntity.ok(UserActivityCountResponse.of(count));
    }

    /**
     * 사용자가 작성한 게시글 목록 조회
     * - JWT에서 userId 추출 (인증 필수)
     * - 해당 사용자가 작성한 게시글만 조회 (댓글 제외)
     * - categories로 여러 카테고리 필터링 (optional)
     * - sortBy로 정렬 방식 선택 (empathy: 공감순, latest: 최신순, default: latest)
     * - 페이징 처리
     *
     * @param categories 카테고리 리스트 (optional, 예: NATURE, CULTURE, TRAFFIC, RESIDENCE, COMMERCIAL, NIGHT, ENVIRONMENT)
     * @param sortBy 정렬 방식 (optional, empathy: 공감순, latest: 최신순, default: latest)
     * @param page 페이지 번호 (default: 0)
     * @param size 페이지 크기 (default: 20)
     * @param authentication Spring Security Authentication (JWT에서 추출, 필수)
     * @return 사용자의 게시글 목록 (페이징)
     */
    @Operation(
            summary = "내 게시글 목록 조회",
            description = "로그인한 사용자가 작성한 게시글 목록을 조회합니다.",
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "게시글 목록 조회 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @GetMapping("/posts")
    public ResponseEntity<PageResponse<PostListResponse>> getUserPosts(
            @Parameter(description = "카테고리 리스트") @RequestParam(required = false) java.util.List<String> categories,
            @Parameter(description = "정렬 방식", example = "latest") @RequestParam(required = false, defaultValue = "latest") String sortBy,
            @Parameter(description = "페이지 번호", example = "0") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "페이지 크기", example = "20") @RequestParam(defaultValue = "20") int size,
            @Parameter(hidden = true) Authentication authentication) {

        // JWT에서 userId 추출 (인증 필수)
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("인증이 필요한 API입니다.");
        }
        String userId = (String) authentication.getPrincipal();

        log.info("GET /v0/users/posts - Getting user posts: userId={}, categories={}, sortBy={}, page={}, size={}",
                userId, categories, sortBy, page, size);

        // 페이징 객체 생성
        Pageable pageable = PageRequest.of(page, size);

        // 서비스 호출
        Page<PostListResponse> posts = userActivityService.getUserPosts(userId, categories, sortBy, pageable);

        log.info("GET /v0/users/posts - Found {} posts by userId={}", posts.getTotalElements(), userId);

        return ResponseEntity.ok(PageResponse.from(posts));
    }

    /**
     * 사용자가 작성한 댓글 개수 조회
     * - JWT에서 userId 추출 (인증 필수)
     * - 해당 사용자가 작성한 댓글 개수 반환
     * - categories로 여러 카테고리 필터링 (optional)
     *
     * @param categories 카테고리 리스트 (optional)
     * @param authentication Spring Security Authentication (JWT에서 추출, 필수)
     * @return 사용자의 댓글 개수
     */
    @Operation(
            summary = "내 댓글 개수 조회",
            description = "로그인한 사용자가 작성한 댓글 개수를 조회합니다.",
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "댓글 개수 조회 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @GetMapping("/comments/count")
    public ResponseEntity<UserActivityCountResponse> getUserCommentsCount(
            @Parameter(description = "카테고리 리스트") @RequestParam(required = false) java.util.List<String> categories,
            @Parameter(hidden = true) Authentication authentication) {

        // JWT에서 userId 추출 (인증 필수)
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("인증이 필요한 API입니다.");
        }
        String userId = (String) authentication.getPrincipal();

        log.info("GET /v0/users/comments/count - Getting user comments count: userId={}, categories={}",
                userId, categories);

        // 서비스 호출
        long count = userActivityService.getUserCommentsCount(userId, categories);

        log.info("GET /v0/users/comments/count - User comments count: userId={}, count={}", userId, count);

        return ResponseEntity.ok(UserActivityCountResponse.of(count));
    }

    /**
     * 사용자가 작성한 댓글 목록 조회
     * - JWT에서 userId 추출 (인증 필수)
     * - 해당 사용자가 작성한 댓글만 조회 (parentPostId가 null이 아닌 게시글)
     * - categories로 여러 카테고리 필터링 (optional)
     * - sortBy로 정렬 방식 선택 (empathy: 공감순, latest: 최신순, default: latest)
     * - 페이징 처리
     *
     * @param categories 카테고리 리스트 (optional)
     * @param sortBy 정렬 방식 (optional, empathy: 공감순, latest: 최신순, default: latest)
     * @param page 페이지 번호 (default: 0)
     * @param size 페이지 크기 (default: 20)
     * @param authentication Spring Security Authentication (JWT에서 추출, 필수)
     * @return 사용자의 댓글 목록 (페이징)
     */
    @Operation(
            summary = "내 댓글 목록 조회",
            description = "로그인한 사용자가 작성한 댓글 목록을 조회합니다.",
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "댓글 목록 조회 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @GetMapping("/comments")
    public ResponseEntity<PageResponse<PostListResponse>> getUserComments(
            @Parameter(description = "카테고리 리스트") @RequestParam(required = false) java.util.List<String> categories,
            @Parameter(description = "정렬 방식", example = "latest") @RequestParam(required = false, defaultValue = "latest") String sortBy,
            @Parameter(description = "페이지 번호", example = "0") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "페이지 크기", example = "20") @RequestParam(defaultValue = "20") int size,
            @Parameter(hidden = true) Authentication authentication) {

        // JWT에서 userId 추출 (인증 필수)
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("인증이 필요한 API입니다.");
        }
        String userId = (String) authentication.getPrincipal();

        log.info("GET /v0/users/comments - Getting user comments: userId={}, categories={}, sortBy={}, page={}, size={}",
                userId, categories, sortBy, page, size);

        // 페이징 객체 생성
        Pageable pageable = PageRequest.of(page, size);

        // 서비스 호출
        Page<PostListResponse> comments = userActivityService.getUserComments(userId, categories, sortBy, pageable);

        log.info("GET /v0/users/comments - Found {} comments by userId={}", comments.getTotalElements(), userId);

        return ResponseEntity.ok(PageResponse.from(comments));
    }

    /**
     * 사용자가 공감한 게시글 개수 조회
     * - JWT에서 userId 추출 (인증 필수)
     * - 해당 사용자가 공감한 게시글 개수 반환
     * - categories로 여러 카테고리 필터링 (optional)
     *
     * @param categories 카테고리 리스트 (optional)
     * @param authentication Spring Security Authentication (JWT에서 추출, 필수)
     * @return 사용자가 공감한 게시글 개수
     */
    @Operation(
            summary = "내가 공감한 게시글 개수 조회",
            description = "로그인한 사용자가 공감한 게시글 개수를 조회합니다.",
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "공감한 게시글 개수 조회 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @GetMapping("/empathy/count")
    public ResponseEntity<UserActivityCountResponse> getUserEmpathyCount(
            @Parameter(description = "카테고리 리스트") @RequestParam(required = false) java.util.List<String> categories,
            @Parameter(hidden = true) Authentication authentication) {

        // JWT에서 userId 추출 (인증 필수)
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("인증이 필요한 API입니다.");
        }
        String userId = (String) authentication.getPrincipal();

        log.info("GET /v0/users/empathy/count - Getting user empathy count: userId={}, categories={}",
                userId, categories);

        // 서비스 호출
        long count = userActivityService.getUserEmpathyCount(userId, categories);

        log.info("GET /v0/users/empathy/count - User empathy count: userId={}, count={}", userId, count);

        return ResponseEntity.ok(UserActivityCountResponse.of(count));
    }

    /**
     * 사용자가 공감한 게시글 목록 조회
     * - JWT에서 userId 추출 (인증 필수)
     * - 해당 사용자가 공감한 게시글만 조회
     * - categories로 여러 카테고리 필터링 (optional)
     * - sortBy로 정렬 방식 선택 (empathy: 공감순, latest: 최신순, default: latest)
     * - 페이징 처리
     *
     * @param categories 카테고리 리스트 (optional)
     * @param sortBy 정렬 방식 (optional, empathy: 공감순, latest: 최신순, default: latest)
     * @param page 페이지 번호 (default: 0)
     * @param size 페이지 크기 (default: 20)
     * @param authentication Spring Security Authentication (JWT에서 추출, 필수)
     * @return 사용자가 공감한 게시글 목록 (페이징)
     */
    @Operation(
            summary = "내가 공감한 게시글 목록 조회",
            description = "로그인한 사용자가 공감한 게시글 목록을 조회합니다.",
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "공감한 게시글 목록 조회 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @GetMapping("/empathy")
    public ResponseEntity<PageResponse<PostListResponse>> getUserEmpathy(
            @Parameter(description = "카테고리 리스트") @RequestParam(required = false) java.util.List<String> categories,
            @Parameter(description = "정렬 방식", example = "latest") @RequestParam(required = false, defaultValue = "latest") String sortBy,
            @Parameter(description = "페이지 번호", example = "0") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "페이지 크기", example = "20") @RequestParam(defaultValue = "20") int size,
            @Parameter(hidden = true) Authentication authentication) {

        // JWT에서 userId 추출 (인증 필수)
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("인증이 필요한 API입니다.");
        }
        String userId = (String) authentication.getPrincipal();

        log.info("GET /v0/users/empathy - Getting user empathy: userId={}, categories={}, sortBy={}, page={}, size={}",
                userId, categories, sortBy, page, size);

        // 페이징 객체 생성
        Pageable pageable = PageRequest.of(page, size);

        // 서비스 호출
        Page<PostListResponse> empathyPosts = userActivityService.getUserEmpathy(userId, categories, sortBy, pageable);

        log.info("GET /v0/users/empathy - Found {} empathy posts by userId={}", empathyPosts.getTotalElements(), userId);

        return ResponseEntity.ok(PageResponse.from(empathyPosts));
    }

    /**
     * 예외 처리: IllegalArgumentException
     * - 인증이 필요한 경우
     * - 401 Unauthorized 응답
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException e) {
        log.warn("IllegalArgumentException: {}", e.getMessage());
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse(e.getMessage()));
    }

    /**
     * 에러 응답 DTO
     */
    public record ErrorResponse(String message) {
    }
}
