package io.github.herbpot.miyobackend.domain.community.service;

import io.github.herbpot.miyobackend.domain.community.dto.PostDetailResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PostListResponse;
import io.github.herbpot.miyobackend.domain.community.entity.PostReadModel;
import io.github.herbpot.miyobackend.domain.community.repository.read.EmpathyRepository;
import io.github.herbpot.miyobackend.domain.community.repository.read.PostReadRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * PostReadService
 * - CQRS Read Model 처리 서비스
 * - 게시글 조회 작업 담당 (목록 조회, 상세 조회)
 * - MySQL Spatial Function을 활용한 위치 기반 검색
 * - 사용자 닉네임은 posts_read 테이블에 비정규화되어 저장됨
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(value = "readTransactionManager", readOnly = true)
public class PostReadService {

    private final PostReadRepository postReadRepository;
    private final EmpathyRepository empathyRepository;
    private final RegionBoundaryService regionBoundaryService;

    /**
     * 기본 검색 반경 (km)
     * - application.properties에서 설정 가능
     */
    @Value("${app.search.default-radius-km:1.0}")
    private Double defaultRadiusKm;

    /**
     * 좌표 기반 주변 게시글 조회
     * - ST_Distance_Sphere를 사용하여 반경 내 게시글 검색
     * - 반경이 null이면 기본값 사용
     * - POINT(경도, 위도) 형식으로 WKT 생성
     * - 공감수 포함하여 반환
     *
     * @param latitude 검색 중심 위도
     * @param longitude 검색 중심 경도
     * @param radiusKm 검색 반경 (km, nullable)
     * @param pageable 페이징 정보
     * @return 반경 내 게시글 목록 (공감수 포함)
     */
    public Page<PostListResponse> findPostsByLocation(
            Double latitude,
            Double longitude,
            Double radiusKm,
            Pageable pageable) {

        // 반경이 null이면 기본값 사용
        double radius = radiusKm != null ? radiusKm : defaultRadiusKm;
        double radiusMeters = radius * 1000; // km를 미터로 변환

        log.info("Finding posts by location: lat={}, lng={}, radius={}km, page={}",
                latitude, longitude, radius, pageable.getPageNumber());

        // WKT(Well-Known Text) 형식: POINT(위도 경도)
        // SRID 4326(WGS 84)에서는 POINT(위도 경도) 순서 사용
        String point = String.format("POINT(%f %f)", latitude, longitude);

        // Spatial 쿼리 실행
        Page<PostReadModel> readModels = postReadRepository.findByLocationWithinRadius(
                point, radiusMeters, pageable
        );

        log.info("Found {} posts within {}km", readModels.getTotalElements(), radius);

        // 게시글 ID 리스트 추출
        java.util.List<Long> postIds = readModels.getContent().stream()
                .map(PostReadModel::getPostId)
                .toList();

        // 공감수 조회 (한번에 조회)
        java.util.Map<Long, Long> empathyCountMap = new java.util.HashMap<>();
        if (!postIds.isEmpty()) {
            java.util.List<Object[]> empathyCounts = empathyRepository.countByPostIds(postIds);
            for (Object[] row : empathyCounts) {
                empathyCountMap.put((Long) row[0], (Long) row[1]);
            }
        }

        // 공감수 기준 내림차순 정렬 (공감수 같으면 최신순)
        java.util.List<PostReadModel> sortedList = readModels.getContent().stream()
                .sorted((a, b) -> {
                    Long countA = empathyCountMap.getOrDefault(a.getPostId(), 0L);
                    Long countB = empathyCountMap.getOrDefault(b.getPostId(), 0L);
                    int countCompare = countB.compareTo(countA); // 내림차순
                    if (countCompare != 0) {
                        return countCompare;
                    }
                    // 공감수 같으면 최신순
                    return b.getCreatedAt().compareTo(a.getCreatedAt());
                })
                .toList();

        // PostReadModel -> PostListResponse 변환 (닉네임, 공감수 포함)
        java.util.List<PostListResponse> responseList = sortedList.stream()
                .map(model -> PostListResponse.from(
                        model,
                        model.getUserNickname(),
                        empathyCountMap.getOrDefault(model.getPostId(), 0L)
                ))
                .toList();

        // Page 재구성
        return new org.springframework.data.domain.PageImpl<>(
                responseList,
                pageable,
                readModels.getTotalElements()
        );
    }

    /**
     * 게시글 상세 조회
     * - postId로 게시글 조회
     * - 삭제된 게시글은 조회 불가
     * - 공감수 및 사용자의 공감 여부 포함
     *
     * @param postId 게시글 ID
     * @param userId 조회하는 사용자 ID (공감 여부 확인용, nullable)
     * @return 게시글 상세 정보 (닉네임, 공감수, 공감 여부 포함)
     * @throws IllegalArgumentException 게시글이 존재하지 않거나 삭제된 경우
     */
    public PostDetailResponse findPostById(Long postId, String userId) {
        log.info("Finding post by id: postId={}, userId={}", postId, userId);

        PostReadModel readModel = postReadRepository.findByPostId(postId)
                .orElseThrow(() -> {
                    log.warn("Post not found: postId={}", postId);
                    return new IllegalArgumentException(
                            "게시글을 찾을 수 없습니다. (postId: " + postId + ")"
                    );
                });

        // 닉네임은 PostReadModel에 저장되어 있음
        String nickname = readModel.getUserNickname();

        // 공감수 조회
        Long empathyCount = empathyRepository.countByPostId(postId);

        // 사용자의 공감 여부 확인
        Boolean isEmpathized = false;
        if (userId != null) {
            isEmpathized = empathyRepository.existsByUserIdAndPostId(userId, postId);
        }

        log.info("Found post: postId={}, userId={}, nickname={}, empathyCount={}, isEmpathized={}",
                readModel.getPostId(), readModel.getUserId(), nickname, empathyCount, isEmpathized);

        return PostDetailResponse.from(readModel, nickname, empathyCount, isEmpathized);
    }

    /**
     * 행정구역(시/군/구) 기반 게시글 조회
     * - Case 1: region만 제공 -> 전체 게시글 중 해당 region 필터링
     * - Case 2: lat, lng + region -> 반경 검색 후 region 필터링
     * - Case 3: lat, lng만 제공 -> 반경 검색만 수행
     *
     * @param latitude 검색 중심 위도 (nullable)
     * @param longitude 검색 중심 경도 (nullable)
     * @param radiusKm 검색 반경 (km, nullable)
     * @param regionName 행정구역명 (예: "종로구", "강남구", nullable)
     * @param pageable 페이징 정보
     * @return 조건에 맞는 게시글 목록
     */
    public Page<PostListResponse> findPostsByRegion(
            Double latitude,
            Double longitude,
            Double radiusKm,
            String regionName,
            Pageable pageable) {

        log.info("Finding posts by region: lat={}, lng={}, radius={}km, region={}, page={}",
                latitude, longitude, radiusKm, regionName, pageable.getPageNumber());

        // Case 1: region만 제공된 경우 - 전체 게시글 조회 후 region 필터링
        if (regionName != null && !regionName.isBlank() && (latitude == null || longitude == null)) {
            log.info("Region-only search mode: region={}", regionName);
            return findPostsByRegionOnly(regionName, pageable);
        }

        // Case 2 & 3: lat, lng가 제공된 경우
        if (latitude == null || longitude == null) {
            throw new IllegalArgumentException("lat와 lng는 필수 파라미터입니다. (region만 검색 시 제외)");
        }

        // 반경이 null이면 기본값 사용
        double radius = radiusKm != null ? radiusKm : defaultRadiusKm;
        double radiusMeters = radius * 1000; // km를 미터로 변환

        // WKT(Well-Known Text) 형식: POINT(위도 경도)
        // SRID 4326(WGS 84)에서는 POINT(위도 경도) 순서 사용
        String point = String.format("POINT(%f %f)", latitude, longitude);

        // 1단계: 반경 내 게시글 조회
        Page<PostReadModel> readModels = postReadRepository.findByLocationWithinRadius(
                point, radiusMeters, pageable
        );

        // 게시글 ID 리스트 추출
        java.util.List<Long> postIds = readModels.getContent().stream()
                .map(PostReadModel::getPostId)
                .toList();

        // 공감수 조회 (한번에 조회)
        java.util.Map<Long, Long> empathyCountMap = new java.util.HashMap<>();
        if (!postIds.isEmpty()) {
            java.util.List<Object[]> empathyCounts = empathyRepository.countByPostIds(postIds);
            for (Object[] row : empathyCounts) {
                empathyCountMap.put((Long) row[0], (Long) row[1]);
            }
        }

        // 2단계: 행정구역 필터링 (regionName이 제공된 경우만)
        java.util.List<PostReadModel> targetList;
        if (regionName != null && !regionName.isBlank()) {
            log.info("Filtering by region: {}", regionName);

            // 지역 경계 내에 있는 게시글만 필터링
            targetList = readModels.getContent().stream()
                    .filter(model -> regionBoundaryService.isPointInRegion(
                            regionName,
                            model.getLatitude(),
                            model.getLongitude()
                    ))
                    .toList();

            log.info("Filtered {} posts in region '{}'", targetList.size(), regionName);
        } else {
            targetList = readModels.getContent();
            log.info("Found {} posts within {}km", readModels.getTotalElements(), radius);
        }

        // 공감수 기준 내림차순 정렬 (공감수 같으면 최신순)
        java.util.List<PostReadModel> sortedList = targetList.stream()
                .sorted((a, b) -> {
                    Long countA = empathyCountMap.getOrDefault(a.getPostId(), 0L);
                    Long countB = empathyCountMap.getOrDefault(b.getPostId(), 0L);
                    int countCompare = countB.compareTo(countA); // 내림차순
                    if (countCompare != 0) {
                        return countCompare;
                    }
                    // 공감수 같으면 최신순
                    return b.getCreatedAt().compareTo(a.getCreatedAt());
                })
                .toList();

        // PostReadModel -> PostListResponse 변환 (닉네임, 공감수 포함)
        java.util.List<PostListResponse> responseList = sortedList.stream()
                .map(model -> PostListResponse.from(
                        model,
                        model.getUserNickname(),
                        empathyCountMap.getOrDefault(model.getPostId(), 0L)
                ))
                .toList();

        // Page 재구성
        return new org.springframework.data.domain.PageImpl<>(
                responseList,
                pageable,
                regionName != null && !regionName.isBlank() ? sortedList.size() : readModels.getTotalElements()
        );
    }

    /**
     * region만으로 게시글 조회 (위치 정보 없이)
     * - 전체 게시글을 조회하여 region 경계 내의 게시글만 필터링
     * - 페이징은 필터링 후 적용
     *
     * @param regionName 행정구역명
     * @param pageable 페이징 정보
     * @return 해당 region 내의 게시글 목록
     */
    private Page<PostListResponse> findPostsByRegionOnly(String regionName, Pageable pageable) {
        log.info("Finding all posts in region: {}", regionName);

        // 전체 게시글 조회 (페이징 없이)
        Pageable unpaged = Pageable.unpaged();
        Page<PostReadModel> allPosts = postReadRepository.findAll(unpaged);

        log.info("Total posts in database: {}", allPosts.getTotalElements());

        // region 경계 내의 게시글만 필터링
        java.util.List<PostReadModel> filteredPosts = allPosts.getContent().stream()
                .filter(model -> regionBoundaryService.isPointInRegion(
                        regionName,
                        model.getLatitude(),
                        model.getLongitude()
                ))
                .toList();

        log.info("Filtered {} posts in region '{}'", filteredPosts.size(), regionName);

        // 게시글 ID 리스트 추출
        java.util.List<Long> postIds = filteredPosts.stream()
                .map(PostReadModel::getPostId)
                .toList();

        // 공감수 조회 (한번에 조회)
        java.util.Map<Long, Long> empathyCountMap = new java.util.HashMap<>();
        if (!postIds.isEmpty()) {
            java.util.List<Object[]> empathyCounts = empathyRepository.countByPostIds(postIds);
            for (Object[] row : empathyCounts) {
                empathyCountMap.put((Long) row[0], (Long) row[1]);
            }
        }

        // 공감수 기준 내림차순 정렬 (공감수 같으면 최신순)
        java.util.List<PostReadModel> sortedList = filteredPosts.stream()
                .sorted((a, b) -> {
                    Long countA = empathyCountMap.getOrDefault(a.getPostId(), 0L);
                    Long countB = empathyCountMap.getOrDefault(b.getPostId(), 0L);
                    int countCompare = countB.compareTo(countA); // 내림차순
                    if (countCompare != 0) {
                        return countCompare;
                    }
                    // 공감수 같으면 최신순
                    return b.getCreatedAt().compareTo(a.getCreatedAt());
                })
                .toList();

        // 페이징 적용
        int start = (int) pageable.getOffset();
        int end = Math.min((start + pageable.getPageSize()), sortedList.size());
        java.util.List<PostReadModel> pagedList = sortedList.subList(start, end);

        // PostReadModel -> PostListResponse 변환
        java.util.List<PostListResponse> responseList = pagedList.stream()
                .map(model -> PostListResponse.from(
                        model,
                        model.getUserNickname(),
                        empathyCountMap.getOrDefault(model.getPostId(), 0L)
                ))
                .toList();

        // Page 재구성
        return new org.springframework.data.domain.PageImpl<>(
                responseList,
                pageable,
                sortedList.size()
        );
    }

    /**
     * TOP 3 게시글 조회
     * - Case 1: region만 제공 -> 해당 지역 전체에서 TOP 3
     * - Case 2: lat, lng만 제공 -> 반경 내에서 TOP 3
     * - Case 3: lat, lng + region -> 반경 내 + region 필터링 후 TOP 3
     * - 공감수 기준으로 내림차순 정렬하여 상위 3개 반환
     *
     * @param latitude 검색 중심 위도 (nullable)
     * @param longitude 검색 중심 경도 (nullable)
     * @param radiusKm 검색 반경 (km, nullable)
     * @param regionName 행정구역명 (nullable, 예: "서울시 강남구 역삼동")
     * @return 공감수 상위 3개 게시글 목록
     */
    public java.util.List<PostListResponse> findTop3PostsByLocation(
            Double latitude,
            Double longitude,
            Double radiusKm,
            String regionName) {

        log.info("Finding top 3 posts: lat={}, lng={}, radius={}km, region={}",
                latitude, longitude, radiusKm, regionName);

        // Case 1: region만 제공된 경우
        if (regionName != null && !regionName.isBlank() && (latitude == null || longitude == null)) {
            log.info("Region-only TOP 3 search mode: region={}", regionName);
            return findTop3PostsByRegionOnly(regionName);
        }

        // Case 2 & 3: lat, lng가 제공된 경우
        if (latitude == null || longitude == null) {
            throw new IllegalArgumentException("lat와 lng는 필수 파라미터입니다. (region만 검색 시 제외)");
        }

        // 반경이 null이면 기본값 사용
        double radius = radiusKm != null ? radiusKm : defaultRadiusKm;
        double radiusMeters = radius * 1000; // km를 미터로 변환

        // WKT(Well-Known Text) 형식: POINT(위도 경도)
        String point = String.format("POINT(%f %f)", latitude, longitude);

        // 반경 내 모든 게시글 조회 (페이징 없이 조회)
        org.springframework.data.domain.Pageable unpaged = org.springframework.data.domain.Pageable.unpaged();
        Page<PostReadModel> readModels = postReadRepository.findByLocationWithinRadius(
                point, radiusMeters, unpaged
        );

        log.info("Found {} total posts within {}km", readModels.getTotalElements(), radius);

        // region 필터링 (제공된 경우)
        java.util.List<PostReadModel> targetList;
        if (regionName != null && !regionName.isBlank()) {
            log.info("Filtering by region: {}", regionName);
            targetList = readModels.getContent().stream()
                    .filter(model -> regionBoundaryService.isPointInRegion(
                            regionName,
                            model.getLatitude(),
                            model.getLongitude()
                    ))
                    .toList();
            log.info("Filtered {} posts in region '{}'", targetList.size(), regionName);
        } else {
            targetList = readModels.getContent();
        }

        // 게시글 ID 리스트 추출
        java.util.List<Long> postIds = targetList.stream()
                .map(PostReadModel::getPostId)
                .toList();

        // 공감수 조회 (한번에 조회)
        java.util.Map<Long, Long> empathyCountMap = new java.util.HashMap<>();
        if (!postIds.isEmpty()) {
            java.util.List<Object[]> empathyCounts = empathyRepository.countByPostIds(postIds);
            for (Object[] row : empathyCounts) {
                empathyCountMap.put((Long) row[0], (Long) row[1]);
            }
        }

        // 공감수 기준 내림차순 정렬 후 상위 3개만 선택
        java.util.List<PostReadModel> top3List = targetList.stream()
                .sorted((a, b) -> {
                    Long countA = empathyCountMap.getOrDefault(a.getPostId(), 0L);
                    Long countB = empathyCountMap.getOrDefault(b.getPostId(), 0L);
                    int countCompare = countB.compareTo(countA); // 내림차순
                    if (countCompare != 0) {
                        return countCompare;
                    }
                    // 공감수 같으면 최신순
                    return b.getCreatedAt().compareTo(a.getCreatedAt());
                })
                .limit(3) // 상위 3개만
                .toList();

        log.info("Selected top {} posts", top3List.size());

        // PostReadModel -> PostListResponse 변환 (닉네임, 공감수 포함)
        return top3List.stream()
                .map(model -> PostListResponse.from(
                        model,
                        model.getUserNickname(),
                        empathyCountMap.getOrDefault(model.getPostId(), 0L)
                ))
                .toList();
    }

    /**
     * region만으로 TOP 3 게시글 조회
     * - 전체 게시글 중 해당 region의 게시글만 필터링하여 TOP 3 선택
     *
     * @param regionName 행정구역명
     * @return TOP 3 게시글 목록
     */
    private java.util.List<PostListResponse> findTop3PostsByRegionOnly(String regionName) {
        log.info("Finding TOP 3 posts in region: {}", regionName);

        // 전체 게시글 조회 (페이징 없이)
        Pageable unpaged = Pageable.unpaged();
        Page<PostReadModel> allPosts = postReadRepository.findAll(unpaged);

        // region 경계 내의 게시글만 필터링
        java.util.List<PostReadModel> filteredPosts = allPosts.getContent().stream()
                .filter(model -> regionBoundaryService.isPointInRegion(
                        regionName,
                        model.getLatitude(),
                        model.getLongitude()
                ))
                .toList();

        log.info("Filtered {} posts in region '{}'", filteredPosts.size(), regionName);

        // 게시글 ID 리스트 추출
        java.util.List<Long> postIds = filteredPosts.stream()
                .map(PostReadModel::getPostId)
                .toList();

        // 공감수 조회 (한번에 조회)
        java.util.Map<Long, Long> empathyCountMap = new java.util.HashMap<>();
        if (!postIds.isEmpty()) {
            java.util.List<Object[]> empathyCounts = empathyRepository.countByPostIds(postIds);
            for (Object[] row : empathyCounts) {
                empathyCountMap.put((Long) row[0], (Long) row[1]);
            }
        }

        // 공감수 기준 내림차순 정렬 후 상위 3개만 선택
        java.util.List<PostReadModel> top3List = filteredPosts.stream()
                .sorted((a, b) -> {
                    Long countA = empathyCountMap.getOrDefault(a.getPostId(), 0L);
                    Long countB = empathyCountMap.getOrDefault(b.getPostId(), 0L);
                    int countCompare = countB.compareTo(countA); // 내림차순
                    if (countCompare != 0) {
                        return countCompare;
                    }
                    // 공감수 같으면 최신순
                    return b.getCreatedAt().compareTo(a.getCreatedAt());
                })
                .limit(3) // 상위 3개만
                .toList();

        log.info("Selected top {} posts", top3List.size());

        // PostReadModel -> PostListResponse 변환
        return top3List.stream()
                .map(model -> PostListResponse.from(
                        model,
                        model.getUserNickname(),
                        empathyCountMap.getOrDefault(model.getPostId(), 0L)
                ))
                .toList();
    }
}
