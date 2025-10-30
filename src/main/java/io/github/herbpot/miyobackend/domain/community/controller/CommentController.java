package io.github.herbpot.miyobackend.domain.community.controller;

import io.github.herbpot.miyobackend.domain.community.dto.CommentCreateRequest;
import io.github.herbpot.miyobackend.domain.community.dto.CommentResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PageResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PostListResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PostResponse;
import io.github.herbpot.miyobackend.domain.community.service.CommentService;
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
@Tag(name = "댓글", description = "댓글 작성 및 조회 API")
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
    @Operation(
            summary = "댓글 작성",
            description = "게시글에 댓글을 작성합니다. JWT 토큰이 필요하며, 위치 정보와 카테고리는 부모 게시글로부터 상속됩니다.",
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "댓글이 성공적으로 작성되었습니다",
                    content = @Content(schema = @Schema(implementation = PostResponse.class))
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청 (Validation 실패 또는 부모 게시글 없음)"),
            @ApiResponse(responseCode = "401", description = "인증 실패 (JWT 토큰 없음 또는 만료)")
    })
    @PostMapping
    public ResponseEntity<PostResponse> createComment(
            @Valid @RequestBody CommentCreateRequest request,
            @Parameter(hidden = true) Authentication authentication,
            @Parameter(hidden = true) @RequestHeader("Authorization") String token) {

        // JWT에서 userId 추출
        String userId = (String) authentication.getPrincipal();

        log.info("POST /v0/comments - Creating comment: userId={}, parentPostId={}",
                userId, request.getParentPostId());

        PostResponse response = commentService.createComment(request, userId, token);

        log.info("POST /v0/comments - Comment created: postId={}, parentPostId={}",
                response.getPostId(), response.getParentPostId());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 특정 게시글의 댓글 목록 조회 (대댓글 포함)
     * - Query Parameter로 parentPostId, page, size 수신
     * - 해당 게시글의 댓글만 조회
     * - 각 댓글의 대댓글(2단계)까지 포함하여 반환
     * - 최신순으로 정렬
     * - 페이징 처리
     *
     * @param parentPostId 부모 게시글 ID
     * @param page 페이지 번호 (default: 0)
     * @param size 페이지 크기 (default: 20)
     * @return 댓글 목록 (대댓글 포함, 페이징)
     */
    @Operation(
            summary = "댓글 목록 조회",
            description = "특정 게시글의 댓글 목록을 최신순으로 조회합니다. 각 댓글의 대댓글도 함께 반환됩니다. 페이징을 지원합니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "댓글 목록 조회 성공"
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청")
    })
    @GetMapping
    public ResponseEntity<PageResponse<CommentResponse>> getComments(
            @Parameter(description = "부모 게시글 ID", example = "1", required = true)
            @RequestParam Long parentPostId,
            @Parameter(description = "페이지 번호 (0부터 시작)", example = "0")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "페이지 크기", example = "20")
            @RequestParam(defaultValue = "20") int size) {

        log.info("GET /v0/comments - Getting comments: parentPostId={}, page={}, size={}",
                parentPostId, page, size);

        // 페이징 객체 생성
        Pageable pageable = PageRequest.of(page, size);

        // 서비스 호출
        Page<CommentResponse> comments = commentService.getCommentsByPostId(parentPostId, pageable);

        log.info("GET /v0/comments - Found {} comments", comments.getTotalElements());

        // PageResponse로 변환하여 반환
        return ResponseEntity.ok(PageResponse.from(comments));
    }

}
