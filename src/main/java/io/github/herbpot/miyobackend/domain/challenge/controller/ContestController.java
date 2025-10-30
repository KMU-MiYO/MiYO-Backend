package io.github.herbpot.miyobackend.domain.challenge.controller;

import io.github.herbpot.miyobackend.domain.challenge.dto.*;
import io.github.herbpot.miyobackend.domain.challenge.service.ContestPostService;
import io.github.herbpot.miyobackend.domain.challenge.service.ContestService;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * ContestController
 * - 공모전 관련 API
 * - 공모전 조회, 참가, 제출물 작성 등
 * - JWT 인증 필요
 */
@Tag(name = "공모전 API", description = "공모전 조회, 참가, 제출물 관리 API")
@Slf4j
@RestController
@RequestMapping("/v0/contests")
@RequiredArgsConstructor
public class ContestController {

    private final ContestService contestService;
    private final ContestPostService contestPostService;

    /**
     * 진행 중인 공모전 목록 조회
     * - 인증 불필요
     * - 최소 정보만 반환 (contestId, title, host, category)
     *
     * @return 진행 중인 공모전 목록 (200 OK)
     */
    @Operation(
            summary = "진행 중인 공모전 목록 조회",
            description = """
                    현재 진행 중인 모든 공모전 목록을 조회합니다.

                    - 인증 불필요 (공개 API)
                    - 요약 정보만 반환 (contestId, title, host, category)
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = ContestListResponse.class))
            )
    })
    @GetMapping
    public ResponseEntity<List<ContestListResponse>> getActiveContests() {
        log.info("GET /v0/contests - Getting active contests");
        List<ContestListResponse> contests = contestService.getActiveContestsList();
        return ResponseEntity.ok(contests);
    }

    /**
     * 특정 공모전 상세 조회
     * - JWT 인증 필요 (isParticipant 확인)
     *
     * @param contestId 공모전 ID
     * @param authentication Spring Security Authentication
     * @return 공모전 상세 정보 (200 OK)
     */
    @Operation(
            summary = "공모전 상세 조회",
            description = """
                    특정 공모전의 상세 정보를 조회합니다.

                    - 공모전 상세 정보 반환
                    - 사용자 참가 여부 포함
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = ContestResponse.class))
            ),
            @ApiResponse(responseCode = "404", description = "공모전을 찾을 수 없음"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @GetMapping("/{contestId}")
    public ResponseEntity<ContestResponse> getContestById(
            @Parameter(description = "공모전 ID", required = true)
            @PathVariable Long contestId,
            @Parameter(hidden = true) Authentication authentication) {

        String userId = (String) authentication.getPrincipal();
        log.info("GET /v0/contests/{} - Getting contest details: userId={}", contestId, userId);

        ContestResponse contest = contestService.getContestById(contestId, userId);

        return ResponseEntity.ok(contest);
    }

    /**
     * 공모전 참가
     *
     * @param contestId 공모전 ID
     * @param authentication Spring Security Authentication
     * @return 201 Created
     */
    @Operation(
            summary = "공모전 참가",
            description = """
                    특정 공모전에 참가 신청합니다.

                    - 공모전 참가 등록
                    - 중복 참가 방지
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "참가 성공"),
            @ApiResponse(responseCode = "404", description = "공모전을 찾을 수 없음"),
            @ApiResponse(responseCode = "400", description = "이미 참가한 공모전"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @PostMapping("/{contestId}/join")
    public ResponseEntity<Void> joinContest(
            @Parameter(description = "공모전 ID", required = true)
            @PathVariable Long contestId,
            @Parameter(hidden = true) Authentication authentication) {

        String userId = (String) authentication.getPrincipal();
        log.info("POST /v0/contests/{}/join - Joining contest: userId={}", contestId, userId);

        contestService.joinContest(contestId, userId);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /**
     * 사용자가 참가한 공모전 목록 조회
     * - 최소 정보만 반환 (contestId, title, host, category)
     *
     * @param authentication Spring Security Authentication
     * @return 참가한 공모전 목록 (200 OK)
     */
    @Operation(
            summary = "내가 참가한 공모전 목록 조회",
            description = """
                    현재 사용자가 참가한 모든 공모전 목록을 조회합니다.

                    - 참가 등록한 공모전만 반환
                    - 요약 정보만 포함
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = ContestListResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @GetMapping("/my")
    public ResponseEntity<List<ContestListResponse>> getMyContests(
            @Parameter(hidden = true) Authentication authentication) {
        String userId = (String) authentication.getPrincipal();
        log.info("GET /v0/contests/my - Getting user's contests: userId={}", userId);

        List<ContestListResponse> contests = contestService.getMyContestsList(userId);
        return ResponseEntity.ok(contests);
    }

    /**
     * 공모전 제출물 작성
     *
     * @param contestId 공모전 ID
     * @param request 제출물 작성 요청
     * @param authentication Spring Security Authentication
     * @return 생성된 제출물 정보 (201 Created)
     */
    @Operation(
            summary = "공모전 제출물 작성",
            description = """
                    특정 공모전에 제출물을 작성합니다.

                    - 텍스트 및 이미지 포함 가능
                    - 공모전 참가자만 작성 가능
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "제출물 작성 성공",
                    content = @Content(schema = @Schema(implementation = ContestPostResponse.class))
            ),
            @ApiResponse(responseCode = "404", description = "공모전을 찾을 수 없음"),
            @ApiResponse(responseCode = "403", description = "공모전에 참가하지 않은 사용자"),
            @ApiResponse(responseCode = "400", description = "잘못된 요청 데이터"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @PostMapping("/{contestId}/posts")
    public ResponseEntity<ContestPostResponse> createPost(
            @Parameter(description = "공모전 ID", required = true)
            @PathVariable Long contestId,
            @Valid @RequestBody ContestPostCreateRequest request,
            @Parameter(hidden = true) Authentication authentication,
            @Parameter(hidden = true) @RequestHeader("Authorization") String token) {

        String userId = (String) authentication.getPrincipal();
        log.info("POST /v0/contests/{}/posts - Creating post: userId={}", contestId, userId);

        ContestPostResponse response = contestPostService.createPost(contestId, request, userId, token);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 공모전 제출물 목록 조회 (요약 정보)
     * - title, userId, imagePath, empathy, createdAt만 반환
     * - 정렬: empathy (공감순) 또는 createdAt (최신순, 기본값)
     *
     * @param contestId 공모전 ID
     * @param sortBy 정렬 기준 (empathy 또는 createdAt, 기본값: createdAt)
     * @param pageable 페이징 정보
     * @return 제출물 요약 목록 (200 OK)
     */
    @Operation(
            summary = "공모전 제출물 목록 조회",
            description = """
                    특정 공모전의 제출물 목록을 조회합니다.

                    - 요약 정보만 반환 (title, userId, imagePath, empathy, createdAt)
                    - 정렬 옵션: createdAt (최신순, 기본값), empathy (공감순)
                    - 페이징 지원 (기본 20개)
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = ContestPostSummaryResponse.class))
            ),
            @ApiResponse(responseCode = "404", description = "공모전을 찾을 수 없음")
    })
    @GetMapping("/{contestId}/posts")
    public ResponseEntity<Page<ContestPostSummaryResponse>> getPostsByContestId(
            @Parameter(description = "공모전 ID", required = true)
            @PathVariable Long contestId,
            @Parameter(description = "정렬 기준 (createdAt 또는 empathy)", example = "createdAt")
            @RequestParam(value = "sortBy", defaultValue = "createdAt") String sortBy,
            @Parameter(description = "페이징 정보 (기본 20개)")
            @PageableDefault(size = 20) Pageable pageable,
            @Parameter(hidden = true)
            @RequestHeader("Authorization") String token) {

        log.info("GET /v0/contests/{}/posts - Getting posts: sortBy={}, page={}", contestId, sortBy, pageable.getPageNumber());

        Page<ContestPostSummaryResponse> posts = contestPostService.getPostsSummaryByContestId(contestId, sortBy, pageable, token);
        return ResponseEntity.ok(posts);
    }

    /**
     * 공모전 제출물 상세 조회
     *
     * @param contestId 공모전 ID (현재는 검증용)
     * @param postId 제출물 ID
     * @return 제출물 상세 정보 (200 OK)
     */
    @Operation(
            summary = "공모전 제출물 상세 조회",
            description = """
                    특정 공모전 제출물의 상세 정보를 조회합니다.

                    - 제출물의 모든 정보 반환
                    - 댓글은 별도 API로 조회
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = ContestPostResponse.class))
            ),
            @ApiResponse(responseCode = "404", description = "제출물을 찾을 수 없음")
    })
    @GetMapping("/{contestId}/posts/{postId}")
    public ResponseEntity<ContestPostResponse> getPostById(
            @Parameter(description = "공모전 ID", required = true)
            @PathVariable Long contestId,
            @Parameter(description = "제출물 ID", required = true)
            @PathVariable Long postId,
            @Parameter(hidden = true) @RequestHeader("Authorization") String token) {

        log.info("GET /v0/contests/{}/posts/{} - Getting post details", contestId, postId);

        ContestPostResponse post = contestPostService.getPostById(postId, token);
        return ResponseEntity.ok(post);
    }

    /**
     * 제출물에 댓글 작성
     *
     * @param postId 부모 제출물 ID
     * @param request 댓글 작성 요청
     * @param authentication Spring Security Authentication
     * @return 생성된 댓글 정보 (201 Created)
     */
    @Operation(
            summary = "제출물에 댓글 작성",
            description = """
                    특정 제출물에 댓글을 작성합니다.

                    - 텍스트 댓글 작성
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "댓글 작성 성공",
                    content = @Content(schema = @Schema(implementation = ContestPostResponse.class))
            ),
            @ApiResponse(responseCode = "404", description = "제출물을 찾을 수 없음"),
            @ApiResponse(responseCode = "400", description = "잘못된 요청 데이터"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @PostMapping("/posts/{postId}/comments")
    public ResponseEntity<ContestPostResponse> createComment(
            @Parameter(description = "제출물 ID", required = true)
            @PathVariable Long postId,
            @Valid @RequestBody ContestPostCommentRequest request,
            @Parameter(hidden = true) Authentication authentication,
            @Parameter(hidden = true) @RequestHeader("Authorization") String token) {

        String userId = (String) authentication.getPrincipal();
        log.info("POST /v0/contests/posts/{}/comments - Creating comment: userId={}", postId, userId);

        ContestPostResponse response = contestPostService.createComment(postId, request, userId, token);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 제출물의 댓글 목록 조회
     *
     * @param postId 부모 제출물 ID
     * @param pageable 페이징 정보
     * @return 댓글 목록 (200 OK)
     */
    @Operation(
            summary = "제출물의 댓글 목록 조회",
            description = """
                    특정 제출물의 댓글 목록을 조회합니다.

                    - 시간순 정렬 (오래된 순)
                    - 페이징 지원 (기본 20개)
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = ContestPostResponse.class))
            ),
            @ApiResponse(responseCode = "404", description = "제출물을 찾을 수 없음")
    })
    @GetMapping("/posts/{postId}/comments")
    public ResponseEntity<Page<ContestPostResponse>> getCommentsByPostId(
            @Parameter(description = "제출물 ID", required = true)
            @PathVariable Long postId,
            @Parameter(description = "페이징 정보 (기본 20개, 시간순 정렬)")
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.ASC) Pageable pageable,
            @Parameter(hidden = true) @RequestHeader("Authorization") String token) {

        log.info("GET /v0/contests/posts/{}/comments - Getting comments: page={}", postId, pageable.getPageNumber());

        Page<ContestPostResponse> comments = contestPostService.getCommentsByPostId(postId, pageable, token);
        return ResponseEntity.ok(comments);
    }

    /**
     * 제출물 공감 추가
     *
     * @param postId 제출물 ID
     * @param authentication Spring Security Authentication
     * @return 200 OK
     */
    @Operation(
            summary = "제출물 공감 추가",
            description = """
                    특정 제출물에 공감(좋아요)을 추가합니다.

                    - 중복 공감 방지
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "공감 추가 성공"),
            @ApiResponse(responseCode = "404", description = "제출물을 찾을 수 없음"),
            @ApiResponse(responseCode = "400", description = "이미 공감한 제출물"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @PostMapping("/posts/{postId}/empathy")
    public ResponseEntity<Void> addEmpathy(
            @Parameter(description = "제출물 ID", required = true)
            @PathVariable Long postId,
            @Parameter(hidden = true) Authentication authentication) {

        String userId = (String) authentication.getPrincipal();
        log.info("POST /v0/contests/posts/{}/empathy - Adding empathy: userId={}", postId, userId);

        contestPostService.addEmpathy(postId, userId);

        return ResponseEntity.ok().build();
    }

    /**
     * 제출물 공감 취소
     *
     * @param postId 제출물 ID
     * @param authentication Spring Security Authentication
     * @return 200 OK
     */
    @Operation(
            summary = "제출물 공감 취소",
            description = """
                    특정 제출물의 공감(좋아요)을 취소합니다.

                    - 기존에 공감한 경우에만 취소 가능
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "공감 취소 성공"),
            @ApiResponse(responseCode = "404", description = "제출물 또는 공감 기록을 찾을 수 없음"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @DeleteMapping("/posts/{postId}/empathy")
    public ResponseEntity<Void> removeEmpathy(
            @Parameter(description = "제출물 ID", required = true)
            @PathVariable Long postId,
            @Parameter(hidden = true) Authentication authentication) {

        String userId = (String) authentication.getPrincipal();
        log.info("DELETE /v0/contests/posts/{}/empathy - Removing empathy: userId={}", postId, userId);

        contestPostService.removeEmpathy(postId, userId);

        return ResponseEntity.ok().build();
    }
}
