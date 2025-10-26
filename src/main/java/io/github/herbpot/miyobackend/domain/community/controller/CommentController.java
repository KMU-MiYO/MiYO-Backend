package io.github.herbpot.miyobackend.domain.community.controller;

import io.github.herbpot.miyobackend.domain.community.dto.CommentCreateRequest;
import io.github.herbpot.miyobackend.domain.community.dto.PageResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PostListResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PostResponse;
import io.github.herbpot.miyobackend.domain.community.service.CommentService;
import jakarta.validation.Valid;
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
 * CommentController
 * - 댓글 작성, 조회 API
 * - POST /v0/comments: 댓글 작성
 * - GET /v0/comments: 특정 게시글의 댓글 목록 조회
 * - 댓글 삭제는 POST /v0/posts/{postId} (DELETE) 사용 (게시글과 공통)
 * - JWT 인증 필요 (조회는 선택)
 */
@Slf4j
@RestController
@RequestMapping("/v0/comments")
@RequiredArgsConstructor
public class CommentController {

    private final CommentService commentService;

    /**
     * 댓글 작성
     * - JWT에서 userId 추출하여 사용
     * - Request Body를 통해 댓글 정보 수신
     * - Validation 수행 (@Valid)
     * - 부모 게시글로부터 위치 정보 상속
     * - Write DB에 저장 후 Redis 이벤트 발행
     * - 201 Created 응답
     *
     * @param request 댓글 작성 요청
     * @param authentication Spring Security Authentication (JWT에서 추출한 userId 포함)
     * @return 생성된 댓글 정보 (201 Created)
     */
    @PostMapping
    public ResponseEntity<PostResponse> createComment(
            @Valid @RequestBody CommentCreateRequest request,
            Authentication authentication) {

        // JWT에서 userId 추출
        String userId = (String) authentication.getPrincipal();

        log.info("POST /v0/comments - Creating comment: userId={}, parentPostId={}",
                userId, request.getParentPostId());

        PostResponse response = commentService.createComment(request, userId);

        log.info("POST /v0/comments - Comment created: postId={}, parentPostId={}",
                response.getPostId(), response.getParentPostId());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 특정 게시글의 댓글 목록 조회
     * - Query Parameter로 parentPostId, page, size 수신
     * - 해당 게시글의 댓글만 조회
     * - 최신순으로 정렬
     * - 페이징 처리
     *
     * @param parentPostId 부모 게시글 ID
     * @param page 페이지 번호 (default: 0)
     * @param size 페이지 크기 (default: 20)
     * @return 댓글 목록 (페이징)
     */
    @GetMapping
    public ResponseEntity<PageResponse<PostListResponse>> getComments(
            @RequestParam Long parentPostId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        log.info("GET /v0/comments - Getting comments: parentPostId={}, page={}, size={}",
                parentPostId, page, size);

        // 페이징 객체 생성
        Pageable pageable = PageRequest.of(page, size);

        // 서비스 호출
        Page<PostListResponse> comments = commentService.getCommentsByPostId(parentPostId, pageable);

        log.info("GET /v0/comments - Found {} comments", comments.getTotalElements());

        // PageResponse로 변환하여 반환
        return ResponseEntity.ok(PageResponse.from(comments));
    }

}
