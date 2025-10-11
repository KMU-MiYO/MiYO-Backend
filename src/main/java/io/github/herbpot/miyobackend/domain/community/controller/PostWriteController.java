package io.github.herbpot.miyobackend.domain.community.controller;

import io.github.herbpot.miyobackend.domain.community.dto.PostCreateRequest;
import io.github.herbpot.miyobackend.domain.community.dto.PostResponse;
import io.github.herbpot.miyobackend.domain.community.service.PostWriteService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * PostWriteController
 * - 게시글 쓰기 작업 API (CQRS Write)
 * - POST /v0/posts: 게시글 작성
 * - DELETE /v0/posts: 게시글 삭제
 */
@Slf4j
@RestController
@RequestMapping("/v0/posts")
@RequiredArgsConstructor
public class PostWriteController {

    private final PostWriteService postWriteService;

    /**
     * 게시글 작성
     * - Request Body를 통해 게시글 정보 수신
     * - Validation 수행 (@Valid)
     * - Write DB에 저장 후 Redis 이벤트 발행
     * - 201 Created 응답
     *
     * @param request 게시글 작성 요청
     * @return 생성된 게시글 정보 (201 Created)
     */
    @PostMapping
    public ResponseEntity<PostResponse> createPost(@Valid @RequestBody PostCreateRequest request) {
        log.info("POST /v0/posts - Creating post: userEmail={}", request.getUserId());

        PostResponse response = postWriteService.createPost(request);

        log.info("POST /v0/posts - Post created: postId={}", response.getPostId());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 게시글 삭제 (소프트 삭제)
     * - Query Parameter로 postId, userEmail 수신
     * - 본인이 작성한 게시글만 삭제 가능
     * - Write DB에서 소프트 삭제 후 Redis 이벤트 발행
     * - 204 No Content 응답
     *
     * @param postId 삭제할 게시글 ID
     * @param userId 요청자 이메일 (본인 확인용)
     * @return 204 No Content
     * @throws IllegalArgumentException 게시글이 존재하지 않거나 권한이 없는 경우 (400 Bad Request로 변환됨)
     */
    @DeleteMapping
    public ResponseEntity<Void> deletePost(
            @RequestParam Long postId,
            @RequestParam Long userId) {

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
