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
     * - Query Parameter로 lat, lng, radius(optional), region(optional), categories(optional), sortBy(optional), page, size 수신
     * - MySQL Spatial Function을 활용한 반경 검색
     * - region만 제공되면 해당 행정구역의 모든 게시글 조회
     * - lat, lng + region이 제공되면 반경 검색 후 region 필터링
     * - categories로 여러 카테고리 필터링 (optional, 예: NATURE,CULTURE 또는 ?categories=NATURE&categories=CULTURE)
     * - sortBy로 정렬 방식 선택 (empathy: 공감순, latest: 최신순, default: empathy)
     * - 페이징 처리
     *
     * @param lat 검색 중심 위도 (optional - region만 검색 시 불필요)
     * @param lng 검색 중심 경도 (optional - region만 검색 시 불필요)
     * @param radius 검색 반경 (km, optional, default: 1.0)
     * @param region 행정구역명 (optional, 예: "종로구", "강남구")
     * @param categories 카테고리 리스트 (optional, 예: NATURE, CULTURE, TRAFFIC, RESIDENCE, COMMERCIAL, NIGHT, ENVIRONMENT)
     * @param sortBy 정렬 방식 (optional, empathy: 공감순, latest: 최신순, default: empathy)
     * @param page 페이지 번호 (default: 0)
     * @param size 페이지 크기 (default: 20)
     * @return 반경 내 게시글 목록 (페이징)
     */
    @GetMapping("/cord")
    public ResponseEntity<PageResponse<PostListResponse>> findPostsByLocation(
            @RequestParam(required = false) Double lat,
            @RequestParam(required = false) Double lng,
            @RequestParam(required = false) Double radius,
            @RequestParam(required = false) String region,
            @RequestParam(required = false) java.util.List<String> categories,
            @RequestParam(required = false, defaultValue = "empathy") String sortBy,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        log.info("GET /v0/posts/cord - Finding posts: lat={}, lng={}, radius={}, region={}, categories={}, sortBy={}, page={}, size={}",
                lat, lng, radius, region, categories, sortBy, page, size);

        // 페이징 객체 생성
        Pageable pageable = PageRequest.of(page, size);

        // 서비스 호출 (categories 파라미터 추가)
        Page<PostListResponse> posts = postReadService.findPostsByRegion(
                lat, lng, radius, region, categories, sortBy, pageable
        );

        log.info("GET /v0/posts/cord - Found {} posts", posts.getTotalElements());

        // PageResponse로 변환하여 반환
        return ResponseEntity.ok(PageResponse.from(posts));
    }

    /**
     * 게시글 상세 조회
     * - Query Parameter로 postId 수신
     * - JWT에서 userId 추출 (인증된 경우에만)
     * - 삭제되지 않은 게시글만 조회 가능
     * - content를 포함한 전체 정보 반환
     * - 공감수 및 사용자의 공감 여부 포함
     *
     * @param postId 게시글 ID
     * @param authentication Spring Security Authentication (JWT에서 추출, optional)
     * @return 게시글 상세 정보 (닉네임, 공감수, 공감 여부 포함)
     * @throws IllegalArgumentException 게시글이 존재하지 않거나 삭제된 경우 (404 Not Found로 변환됨)
     */
    @GetMapping("/id")
    public ResponseEntity<PostDetailResponse> findPostById(
            @RequestParam Long postId,
            org.springframework.security.core.Authentication authentication) {

        // JWT에서 userId 추출 (인증되지 않은 경우 null)
        String userId = null;
        if (authentication != null && authentication.isAuthenticated()) {
            userId = (String) authentication.getPrincipal();
        }

        log.info("GET /v0/posts/id - Finding post by id: postId={}, userId={}", postId, userId);

        PostDetailResponse response = postReadService.findPostById(postId, userId);

        log.info("GET /v0/posts/id - Found post: postId={}", postId);

        return ResponseEntity.ok(response);
    }

    /**
     * 사용자별 게시글 조회
     * - JWT 토큰에서 userId 추출 (인증 필수)
     * - 해당 사용자가 작성한 게시글만 조회 (댓글 제외)
     * - categories로 여러 카테고리 필터링 (optional)
     * - sortBy로 정렬 방식 선택 (empathy: 공감순, latest: 최신순, default: empathy)
     * - 페이징 처리
     *
     * @param categories 카테고리 리스트 (optional, 예: NATURE, CULTURE, TRAFFIC, RESIDENCE, COMMERCIAL, NIGHT, ENVIRONMENT)
     * @param sortBy 정렬 방식 (optional, empathy: 공감순, latest: 최신순, default: empathy)
     * @param page 페이지 번호 (default: 0)
     * @param size 페이지 크기 (default: 20)
     * @param authentication Spring Security Authentication (JWT에서 추출, 필수)
     * @return 사용자의 게시글 목록 (페이징)
     */
    @GetMapping("/my")
    public ResponseEntity<PageResponse<PostListResponse>> findMyPosts(
            @RequestParam(required = false) java.util.List<String> categories,
            @RequestParam(required = false, defaultValue = "empathy") String sortBy,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            org.springframework.security.core.Authentication authentication) {

        // JWT에서 userId 추출 (인증 필수)
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("인증이 필요한 API입니다.");
        }
        String userId = (String) authentication.getPrincipal();

        log.info("GET /v0/posts/my - Finding posts by userId: userId={}, categories={}, sortBy={}, page={}, size={}",
                userId, categories, sortBy, page, size);

        // 페이징 객체 생성
        Pageable pageable = PageRequest.of(page, size);

        // 서비스 호출
        Page<PostListResponse> posts = postReadService.findPostsByUserId(userId, categories, sortBy, pageable);

        log.info("GET /v0/posts/my - Found {} posts by userId={}", posts.getTotalElements(), userId);

        // PageResponse로 변환하여 반환
        return ResponseEntity.ok(PageResponse.from(posts));
    }

    /**
     * TOP 3 게시글 조회
     * - Case 1: lat, lng만 제공 -> 해당 좌표 기준 반경 내 TOP 3
     * - Case 2: region만 제공 -> 해당 지역 전체에서 TOP 3
     * - Case 3: lat, lng + region -> 반경 내 + region 필터링 후 TOP 3
     * - 공감수 기준으로 내림차순 정렬하여 상위 3개 반환
     *
     * @param lat 검색 중심 위도 (optional)
     * @param lng 검색 중심 경도 (optional)
     * @param radius 검색 반경 (km, optional, default: 1.0)
     * @param region 행정구역명 (optional, 예: "서울시 강남구 역삼동")
     * @return TOP 3 게시글 목록 with location 정보
     */
    @GetMapping("/top3")
    public ResponseEntity<Top3PostsResponse> findTop3PostsByLocation(
            @RequestParam(required = false) Double lat,
            @RequestParam(required = false) Double lng,
            @RequestParam(required = false) Double radius,
            @RequestParam(required = false) String region) {

        log.info("GET /v0/posts/top3 - Finding top 3 posts: lat={}, lng={}, radius={}, region={}",
                lat, lng, radius, region);

        java.util.List<PostListResponse> top3Posts = postReadService.findTop3PostsByLocation(
                lat, lng, radius, region
        );

        log.info("GET /v0/posts/top3 - Found {} top posts", top3Posts.size());

        // location 정보 생성
        String locationLabel = (region != null && !region.isBlank())
                ? region + " 순위"
                : "내 주변 순위";

        // location 정보와 함께 응답 구성
        Top3PostsResponse response = new Top3PostsResponse(
                locationLabel,
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
