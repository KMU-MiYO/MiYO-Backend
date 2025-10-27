package io.github.herbpot.miyobackend.domain.challenge.controller;

import io.github.herbpot.miyobackend.domain.challenge.dto.ContestPostCommentRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestPostCreateRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestPostResponse;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestResponse;
import io.github.herbpot.miyobackend.domain.challenge.service.ContestPostService;
import io.github.herbpot.miyobackend.domain.challenge.service.ContestService;
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
@Slf4j
@RestController
@RequestMapping("/v0/contests")
@RequiredArgsConstructor
public class ContestController {

    private final ContestService contestService;
    private final ContestPostService contestPostService;

    /**
     * 진행 중인 공모전 목록 조회
     *
     * @return 진행 중인 공모전 목록 (200 OK)
     */
    @GetMapping
    public ResponseEntity<List<ContestResponse>> getActiveContests() {
        log.info("GET /v0/contests - Getting active contests");
        List<ContestResponse> contests = contestService.getActiveContests();
        return ResponseEntity.ok(contests);
    }

    /**
     * 특정 공모전 상세 조회
     *
     * @param contestId 공모전 ID
     * @return 공모전 상세 정보 (200 OK)
     */
    @GetMapping("/{contestId}")
    public ResponseEntity<ContestResponse> getContestById(@PathVariable Long contestId) {
        log.info("GET /v0/contests/{} - Getting contest details", contestId);

        ContestResponse contest = contestService.getContestById(contestId, null);

        return ResponseEntity.ok(contest);
    }

    /**
     * 공모전 참가
     *
     * @param contestId 공모전 ID
     * @param authentication Spring Security Authentication
     * @return 201 Created
     */
    @PostMapping("/{contestId}/join")
    public ResponseEntity<Void> joinContest(
            @PathVariable Long contestId,
            Authentication authentication) {

        String userId = (String) authentication.getPrincipal();
        log.info("POST /v0/contests/{}/join - Joining contest: userId={}", contestId, userId);

        contestService.joinContest(contestId, userId);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /**
     * 사용자가 참가한 공모전 목록 조회
     *
     * @param authentication Spring Security Authentication
     * @return 참가한 공모전 목록 (200 OK)
     */
    @GetMapping("/my")
    public ResponseEntity<List<ContestResponse>> getMyContests(Authentication authentication) {
        String userId = (String) authentication.getPrincipal();
        log.info("GET /v0/contests/my - Getting user's contests: userId={}", userId);

        List<ContestResponse> contests = contestService.getMyContests(userId);
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
    @PostMapping("/{contestId}/posts")
    public ResponseEntity<ContestPostResponse> createPost(
            @PathVariable Long contestId,
            @Valid @RequestBody ContestPostCreateRequest request,
            Authentication authentication) {

        String userId = (String) authentication.getPrincipal();
        log.info("POST /v0/contests/{}/posts - Creating post: userId={}", contestId, userId);

        ContestPostResponse response = contestPostService.createPost(contestId, request, userId);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 공모전 제출물 목록 조회
     *
     * @param contestId 공모전 ID
     * @param pageable 페이징 정보
     * @return 제출물 목록 (200 OK)
     */
    @GetMapping("/{contestId}/posts")
    public ResponseEntity<Page<ContestPostResponse>> getPostsByContestId(
            @PathVariable Long contestId,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("GET /v0/contests/{}/posts - Getting posts: page={}", contestId, pageable.getPageNumber());

        Page<ContestPostResponse> posts = contestPostService.getPostsByContestId(contestId, pageable);
        return ResponseEntity.ok(posts);
    }

    /**
     * 공모전 제출물 상세 조회
     *
     * @param contestId 공모전 ID (현재는 검증용)
     * @param postId 제출물 ID
     * @return 제출물 상세 정보 (200 OK)
     */
    @GetMapping("/{contestId}/posts/{postId}")
    public ResponseEntity<ContestPostResponse> getPostById(
            @PathVariable Long contestId,
            @PathVariable Long postId) {

        log.info("GET /v0/contests/{}/posts/{} - Getting post details", contestId, postId);

        ContestPostResponse post = contestPostService.getPostById(postId);
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
    @PostMapping("/posts/{postId}/comments")
    public ResponseEntity<ContestPostResponse> createComment(
            @PathVariable Long postId,
            @Valid @RequestBody ContestPostCommentRequest request,
            Authentication authentication) {

        String userId = (String) authentication.getPrincipal();
        log.info("POST /v0/contests/posts/{}/comments - Creating comment: userId={}", postId, userId);

        ContestPostResponse response = contestPostService.createComment(postId, request, userId);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 제출물의 댓글 목록 조회
     *
     * @param postId 부모 제출물 ID
     * @param pageable 페이징 정보
     * @return 댓글 목록 (200 OK)
     */
    @GetMapping("/posts/{postId}/comments")
    public ResponseEntity<Page<ContestPostResponse>> getCommentsByPostId(
            @PathVariable Long postId,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.ASC) Pageable pageable) {

        log.info("GET /v0/contests/posts/{}/comments - Getting comments: page={}", postId, pageable.getPageNumber());

        Page<ContestPostResponse> comments = contestPostService.getCommentsByPostId(postId, pageable);
        return ResponseEntity.ok(comments);
    }

    /**
     * 제출물 공감 추가
     *
     * @param postId 제출물 ID
     * @param authentication Spring Security Authentication
     * @return 200 OK
     */
    @PostMapping("/posts/{postId}/empathy")
    public ResponseEntity<Void> addEmpathy(
            @PathVariable Long postId,
            Authentication authentication) {

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
    @DeleteMapping("/posts/{postId}/empathy")
    public ResponseEntity<Void> removeEmpathy(
            @PathVariable Long postId,
            Authentication authentication) {

        String userId = (String) authentication.getPrincipal();
        log.info("DELETE /v0/contests/posts/{}/empathy - Removing empathy: userId={}", postId, userId);

        contestPostService.removeEmpathy(postId, userId);

        return ResponseEntity.ok().build();
    }
}
