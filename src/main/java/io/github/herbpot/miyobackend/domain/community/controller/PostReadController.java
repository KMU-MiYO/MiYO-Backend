package io.github.herbpot.miyobackend.domain.community.controller;

import io.github.herbpot.miyobackend.domain.community.dto.PageResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PostDetailResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PostListResponse;
import io.github.herbpot.miyobackend.domain.community.service.PostReadService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * PostReadController
 * - 게시글 읽기 작업 API (CQRS Read)
 * - GET /v0/posts/cord: 좌표 기반 주변 게시글 조회
 * - GET /v0/posts/id: 게시글 상세 조회
 */
@Slf4j
@RestController
@RequestMapping("/v0/posts")
@RequiredArgsConstructor
public class PostReadController {

    private final PostReadService postReadService;

    /**
     * 좌표 기반 주변 게시글 조회 (행정구역 필터링 지원)
     * - Query Parameter로 lat, lng, radius(optional), region(optional), page, size 수신
     * - MySQL Spatial Function을 활용한 반경 검색
     * - region 파라미터가 제공되면 해당 시/군/구 경계 내의 게시글만 필터링
     * - 페이징 처리
     *
     * @param lat 검색 중심 위도
     * @param lng 검색 중심 경도
     * @param radius 검색 반경 (km, optional, default: 1.0)
     * @param region 행정구역명 (optional, 예: "종로구", "강남구")
     * @param page 페이지 번호 (default: 0)
     * @param size 페이지 크기 (default: 20)
     * @return 반경 내 게시글 목록 (페이징)
     */
    @GetMapping("/cord")
    public ResponseEntity<PageResponse<PostListResponse>> findPostsByLocation(
            @RequestParam Double lat,
            @RequestParam Double lng,
            @RequestParam(required = false) Double radius,
            @RequestParam(required = false) String region,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        log.info("GET /v0/posts/cord - Finding posts: lat={}, lng={}, radius={}, regon={}, page={}, size={}",
                lat, lng, radius, region, page, size);

        // 페이징 객체 생성
        Pageable pageable = PageRequest.of(page, size);

        // 서비스 호출 (region 파라미터 추가)
        Page<PostListResponse> posts = postReadService.findPostsByRegion(
                lat, lng, radius, region, pageable
        );

        log.info("GET /v0/posts/cord - Found {} posts", posts.getTotalElements());

        // PageResponse로 변환하여 반환
        return ResponseEntity.ok(PageResponse.from(posts));
    }

    /**
     * 게시글 상세 조회
     * - Query Parameter로 postId, userId(optional) 수신
     * - 삭제되지 않은 게시글만 조회 가능
     * - content를 포함한 전체 정보 반환
     * - 공감수 및 사용자의 공감 여부 포함
     *
     * @param postId 게시글 ID
     * @param userId 사용자 ID (공감 여부 확인용, optional)
     * @return 게시글 상세 정보 (닉네임, 공감수, 공감 여부 포함)
     * @throws IllegalArgumentException 게시글이 존재하지 않거나 삭제된 경우 (404 Not Found로 변환됨)
     */
    @GetMapping("/id")
    public ResponseEntity<PostDetailResponse> findPostById(
            @RequestParam Long postId,
            @RequestParam(required = false) Long userId) {
        log.info("GET /v0/posts/id - Finding post by id: postId={}, userId={}", postId, userId);

        PostDetailResponse response = postReadService.findPostById(postId, userId);

        log.info("GET /v0/posts/id - Found post: postId={}", postId);

        return ResponseEntity.ok(response);
    }

    /**
     * 지역별 TOP 3 게시글 조회
     * - Query Parameter로 lat, lng, radius(optional), region(required) 수신
     * - 공감수 기준으로 내림차순 정렬하여 상위 3개 반환
     * - location 필드에 "지역명 순위" 형식으로 응답
     *
     * @param lat 검색 중심 위도
     * @param lng 검색 중심 경도
     * @param radius 검색 반경 (km, optional, default: 1.0)
     * @param region 행정구역명 (required, 예: "서울시 강남구 역삼동")
     * @return TOP 3 게시글 목록 with location 정보
     */
    @GetMapping("/top3")
    public ResponseEntity<Top3PostsResponse> findTop3PostsByLocation(
            @RequestParam Double lat,
            @RequestParam Double lng,
            @RequestParam(required = false) Double radius,
            @RequestParam String region) {

        log.info("GET /v0/posts/top3 - Finding top 3 posts: lat={}, lng={}, radius={}, region={}",
                lat, lng, radius, region);

        java.util.List<PostListResponse> top3Posts = postReadService.findTop3PostsByLocation(
                lat, lng, radius, region
        );

        log.info("GET /v0/posts/top3 - Found {} top posts", top3Posts.size());

        // location 정보와 함께 응답 구성
        Top3PostsResponse response = new Top3PostsResponse(
                region + " 순위",
                top3Posts
        );

        return ResponseEntity.ok(response);
    }

    /**
     * 예외 처리: IllegalArgumentException
     * - 게시글이 존재하지 않는 경우
     * - 404 Not Found 응답
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException e) {
        log.warn("IllegalArgumentException: {}", e.getMessage());
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(new ErrorResponse(e.getMessage()));
    }

    /**
     * 에러 응답 DTO
     */
    public record ErrorResponse(String message) {
    }

    /**
     * TOP 3 게시글 응답 DTO
     */
    public record Top3PostsResponse(
            String location,
            java.util.List<PostListResponse> posts
    ) {
    }
}
