package io.github.herbpot.miyobackend.domain.community.service;

import io.github.herbpot.miyobackend.domain.community.dto.PostListResponse;
import io.github.herbpot.miyobackend.domain.community.entity.PostCategory;
import io.github.herbpot.miyobackend.domain.community.entity.read.PostReadModel;
import io.github.herbpot.miyobackend.domain.community.repository.read.EmpathyReadRepository;
import io.github.herbpot.miyobackend.domain.community.repository.read.PostReadRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

/**
 * UserActivityService
 * - 사용자의 활동 내역 조회 서비스
 * - 사용자가 작성한 게시글, 댓글, 공감한 게시글 조회
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(value = "readTransactionManager", readOnly = true)
public class UserActivityService {

    private final PostReadRepository postReadRepository;
    private final EmpathyReadRepository empathyReadRepository;

    /**
     * 사용자가 작성한 게시글 개수 조회
     * - userId가 일치하고 parentPostId가 null인 게시글만 조회 (댓글 제외)
     * - categories로 여러 카테고리 필터링 (optional)
     *
     * @param userId 사용자 ID
     * @param categoryStrList 카테고리 리스트 (nullable)
     * @return 사용자의 게시글 개수
     */
    public long getUserPostsCount(String userId, List<String> categoryStrList) {
        log.info("Getting user posts count: userId={}, categories={}", userId, categoryStrList);

        // 카테고리 리스트 파싱
        Set<PostCategory> categories = parseCategories(categoryStrList);

        // 사용자의 게시글 조회 (댓글 제외, 전체 조회)
        Page<PostReadModel> readModels = postReadRepository
                .findByUserIdAndParentPostIdIsNullOrderByCreatedAtDesc(userId, Pageable.unpaged());

        // 카테고리 필터링 (categories가 제공된 경우만)
        long count = readModels.getTotalElements();
        if (categories != null && !categories.isEmpty()) {
            count = readModels.getContent().stream()
                    .filter(model -> categories.contains(model.getCategory()))
                    .count();
        }

        log.info("User posts count: userId={}, count={}", userId, count);
        return count;
    }

    /**
     * 사용자가 작성한 댓글 개수 조회
     * - userId가 일치하고 parentPostId가 null이 아닌 게시글만 조회 (댓글만)
     * - categories로 여러 카테고리 필터링 (optional)
     *
     * @param userId 사용자 ID
     * @param categoryStrList 카테고리 리스트 (nullable)
     * @return 사용자의 댓글 개수
     */
    public long getUserCommentsCount(String userId, List<String> categoryStrList) {
        log.info("Getting user comments count: userId={}, categories={}", userId, categoryStrList);

        // 카테고리 리스트 파싱
        Set<PostCategory> categories = parseCategories(categoryStrList);

        // 사용자의 댓글 조회 (게시글 제외, 전체 조회)
        Page<PostReadModel> readModels = postReadRepository
                .findByUserIdAndParentPostIdIsNotNullOrderByCreatedAtDesc(userId, Pageable.unpaged());

        // 카테고리 필터링 (categories가 제공된 경우만)
        long count = readModels.getTotalElements();
        if (categories != null && !categories.isEmpty()) {
            count = readModels.getContent().stream()
                    .filter(model -> categories.contains(model.getCategory()))
                    .count();
        }

        log.info("User comments count: userId={}, count={}", userId, count);
        return count;
    }

    /**
     * 사용자가 공감한 게시글 개수 조회
     * - 사용자가 공감한 게시글 ID 목록을 먼저 조회
     * - categories로 여러 카테고리 필터링 (optional)
     *
     * @param userId 사용자 ID
     * @param categoryStrList 카테고리 리스트 (nullable)
     * @return 사용자가 공감한 게시글 개수
     */
    public long getUserEmpathyCount(String userId, List<String> categoryStrList) {
        log.info("Getting user empathy count: userId={}, categories={}", userId, categoryStrList);

        // 카테고리 리스트 파싱
        Set<PostCategory> categories = parseCategories(categoryStrList);

        // 사용자가 공감한 게시글 ID 목록 조회
        List<Long> empathyPostIds = empathyReadRepository.findPostIdsByUserId(userId);

        if (empathyPostIds.isEmpty()) {
            log.info("User empathy count: userId={}, count=0", userId);
            return 0;
        }

        // 카테고리 필터링 (categories가 제공된 경우만)
        long count = empathyPostIds.size();
        if (categories != null && !categories.isEmpty()) {
            // 게시글 상세 정보 조회
            List<PostReadModel> postModels = empathyPostIds.stream()
                    .map(postReadRepository::findByPostId)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .collect(Collectors.toList());

            count = postModels.stream()
                    .filter(model -> categories.contains(model.getCategory()))
                    .count();
        }

        log.info("User empathy count: userId={}, count={}", userId, count);
        return count;
    }

    /**
     * 사용자가 작성한 게시글 목록 조회
     * - userId가 일치하고 parentPostId가 null인 게시글만 조회 (댓글 제외)
     * - categories로 여러 카테고리 필터링 (optional)
     * - sortBy로 정렬 방식 선택 (empathy: 공감순, latest: 최신순)
     *
     * @param userId 사용자 ID
     * @param categoryStrList 카테고리 리스트 (nullable)
     * @param sortBy 정렬 방식 (empathy: 공감순, latest: 최신순)
     * @param pageable 페이징 정보
     * @return 사용자의 게시글 목록
     */
    public Page<PostListResponse> getUserPosts(
            String userId,
            List<String> categoryStrList,
            String sortBy,
            Pageable pageable) {

        log.info("Getting user posts: userId={}, categories={}, sortBy={}, page={}",
                userId, categoryStrList, sortBy, pageable.getPageNumber());

        // 카테고리 리스트 파싱
        Set<PostCategory> categories = parseCategories(categoryStrList);

        // 사용자의 게시글 조회 (댓글 제외, 전체 조회)
        Page<PostReadModel> readModels = postReadRepository
                .findByUserIdAndParentPostIdIsNullOrderByCreatedAtDesc(userId, Pageable.unpaged());

        log.info("Found {} posts by userId={}", readModels.getTotalElements(), userId);

        // 카테고리 필터링 (categories가 제공된 경우만)
        List<PostReadModel> filteredList = readModels.getContent();
        if (categories != null && !categories.isEmpty()) {
            log.info("Filtering by categories: {}", categories);
            filteredList = filteredList.stream()
                    .filter(model -> categories.contains(model.getCategory()))
                    .collect(Collectors.toList());
            log.info("Filtered {} posts in categories '{}'", filteredList.size(), categories);
        }

        // 공감수 조회 및 정렬
        return buildPageResponse(filteredList, sortBy, pageable);
    }

    /**
     * 사용자가 작성한 댓글 목록 조회
     * - userId가 일치하고 parentPostId가 null이 아닌 게시글만 조회 (댓글만)
     * - categories로 여러 카테고리 필터링 (optional)
     * - sortBy로 정렬 방식 선택 (empathy: 공감순, latest: 최신순)
     *
     * @param userId 사용자 ID
     * @param categoryStrList 카테고리 리스트 (nullable)
     * @param sortBy 정렬 방식 (empathy: 공감순, latest: 최신순)
     * @param pageable 페이징 정보
     * @return 사용자의 댓글 목록
     */
    public Page<PostListResponse> getUserComments(
            String userId,
            List<String> categoryStrList,
            String sortBy,
            Pageable pageable) {

        log.info("Getting user comments: userId={}, categories={}, sortBy={}, page={}",
                userId, categoryStrList, sortBy, pageable.getPageNumber());

        // 카테고리 리스트 파싱
        Set<PostCategory> categories = parseCategories(categoryStrList);

        // 사용자의 댓글 조회 (게시글 제외, 전체 조회)
        Page<PostReadModel> readModels = postReadRepository
                .findByUserIdAndParentPostIdIsNotNullOrderByCreatedAtDesc(userId, Pageable.unpaged());

        log.info("Found {} comments by userId={}", readModels.getTotalElements(), userId);

        // 카테고리 필터링 (categories가 제공된 경우만)
        List<PostReadModel> filteredList = readModels.getContent();
        if (categories != null && !categories.isEmpty()) {
            log.info("Filtering by categories: {}", categories);
            filteredList = filteredList.stream()
                    .filter(model -> categories.contains(model.getCategory()))
                    .collect(Collectors.toList());
            log.info("Filtered {} comments in categories '{}'", filteredList.size(), categories);
        }

        // 공감수 조회 및 정렬
        return buildPageResponse(filteredList, sortBy, pageable);
    }

    /**
     * 사용자가 공감한 게시글 목록 조회
     * - 사용자가 공감한 게시글 ID 목록을 먼저 조회
     * - 해당 게시글들의 상세 정보 조회
     * - categories로 여러 카테고리 필터링 (optional)
     * - sortBy로 정렬 방식 선택 (empathy: 공감순, latest: 최신순)
     *
     * @param userId 사용자 ID
     * @param categoryStrList 카테고리 리스트 (nullable)
     * @param sortBy 정렬 방식 (empathy: 공감순, latest: 최신순)
     * @param pageable 페이징 정보
     * @return 사용자가 공감한 게시글 목록
     */
    public Page<PostListResponse> getUserEmpathy(
            String userId,
            List<String> categoryStrList,
            String sortBy,
            Pageable pageable) {

        log.info("Getting user empathy: userId={}, categories={}, sortBy={}, page={}",
                userId, categoryStrList, sortBy, pageable.getPageNumber());

        // 카테고리 리스트 파싱
        Set<PostCategory> categories = parseCategories(categoryStrList);

        // 사용자가 공감한 게시글 ID 목록 조회
        List<Long> empathyPostIds = empathyReadRepository.findPostIdsByUserId(userId);

        log.info("Found {} empathy posts by userId={}", empathyPostIds.size(), userId);

        if (empathyPostIds.isEmpty()) {
            // 공감한 게시글이 없으면 빈 페이지 반환
            return new PageImpl<>(Collections.emptyList(), pageable, 0);
        }

        // 게시글 상세 정보 조회
        List<PostReadModel> postModels = empathyPostIds.stream()
                .map(postReadRepository::findByPostId)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());

        log.info("Found {} post details for empathy posts", postModels.size());

        // 카테고리 필터링 (categories가 제공된 경우만)
        List<PostReadModel> filteredList = postModels;
        if (categories != null && !categories.isEmpty()) {
            log.info("Filtering by categories: {}", categories);
            filteredList = postModels.stream()
                    .filter(model -> categories.contains(model.getCategory()))
                    .collect(Collectors.toList());
            log.info("Filtered {} posts in categories '{}'", filteredList.size(), categories);
        }

        // 공감수 조회 및 정렬
        return buildPageResponse(filteredList, sortBy, pageable);
    }

    /**
     * 게시글 리스트를 정렬하고 페이징 처리하여 응답 생성
     *
     * @param postList 게시글 리스트
     * @param sortBy 정렬 방식 (empathy: 공감순, latest: 최신순)
     * @param pageable 페이징 정보
     * @return 페이징된 게시글 응답
     */
    private Page<PostListResponse> buildPageResponse(
            List<PostReadModel> postList,
            String sortBy,
            Pageable pageable) {

        if (postList.isEmpty()) {
            return new PageImpl<>(Collections.emptyList(), pageable, 0);
        }

        // 게시글 ID 리스트 추출
        List<Long> postIds = postList.stream()
                .map(PostReadModel::getPostId)
                .collect(Collectors.toList());

        // 공감수 조회 (한번에 조회)
        Map<Long, Long> empathyCountMap = new HashMap<>();
        List<Object[]> empathyCounts = empathyReadRepository.countByPostIds(postIds);
        for (Object[] row : empathyCounts) {
            empathyCountMap.put((Long) row[0], (Long) row[1]);
        }

        // 정렬 방식에 따라 정렬
        List<PostReadModel> sortedList = sortPostList(postList, empathyCountMap, sortBy);

        // 페이징 적용
        int start = (int) pageable.getOffset();
        int end = Math.min((start + pageable.getPageSize()), sortedList.size());
        List<PostReadModel> pagedList = sortedList.subList(start, end);

        // PostReadModel -> PostListResponse 변환 (닉네임, 공감수 포함)
        List<PostListResponse> responseList = pagedList.stream()
                .map(model -> PostListResponse.from(
                        model,
                        model.getUserNickname(),
                        empathyCountMap.getOrDefault(model.getPostId(), 0L)
                ))
                .collect(Collectors.toList());

        // Page 재구성
        return new PageImpl<>(responseList, pageable, sortedList.size());
    }

    /**
     * 게시글 리스트 정렬 헬퍼 메서드
     * - sortBy 파라미터에 따라 공감순 또는 최신순으로 정렬
     *
     * @param postList 정렬할 게시글 리스트
     * @param empathyCountMap 공감수 맵
     * @param sortBy 정렬 방식 (empathy: 공감순, latest: 최신순)
     * @return 정렬된 게시글 리스트
     */
    private List<PostReadModel> sortPostList(
            List<PostReadModel> postList,
            Map<Long, Long> empathyCountMap,
            String sortBy) {

        if ("latest".equalsIgnoreCase(sortBy)) {
            // 최신순 정렬
            return postList.stream()
                    .sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt()))
                    .collect(Collectors.toList());
        } else {
            // 공감순 정렬 (기본값, 공감수 같으면 최신순)
            return postList.stream()
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
                    .collect(Collectors.toList());
        }
    }

    /**
     * 카테고리 문자열 리스트를 PostCategory enum Set으로 파싱
     * - null이거나 빈 리스트이면 null 반환
     * - 유효하지 않은 카테고리명이면 IllegalArgumentException 발생
     *
     * @param categoryStrList 카테고리 문자열 리스트
     * @return PostCategory enum Set 또는 null
     * @throws IllegalArgumentException 유효하지 않은 카테고리명인 경우
     */
    private Set<PostCategory> parseCategories(List<String> categoryStrList) {
        if (categoryStrList == null || categoryStrList.isEmpty()) {
            return null;
        }

        Set<PostCategory> categories = new HashSet<>();
        for (String categoryStr : categoryStrList) {
            if (categoryStr != null && !categoryStr.isBlank()) {
                try {
                    categories.add(PostCategory.valueOf(categoryStr.toUpperCase()));
                } catch (IllegalArgumentException e) {
                    log.warn("Invalid category: {}", categoryStr);
                    throw new IllegalArgumentException(
                            "유효하지 않은 카테고리입니다: " + categoryStr + ". 사용 가능한 카테고리: NATURE, CULTURE, TRAFFIC, RESIDENCE, COMMERCIAL, NIGHT, ENVIRONMENT"
                    );
                }
            }
        }

        return categories.isEmpty() ? null : categories;
    }
}
