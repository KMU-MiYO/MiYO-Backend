package io.github.herbpot.miyobackend.domain.community.service;

import io.github.herbpot.miyobackend.client.UserServiceClient;
import io.github.herbpot.miyobackend.domain.community.dto.CommentCreateRequest;
import io.github.herbpot.miyobackend.domain.community.dto.CommentEvent;
import io.github.herbpot.miyobackend.domain.community.dto.CommentResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PostListResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PostResponse;
import io.github.herbpot.miyobackend.domain.community.entity.write.Post;
import io.github.herbpot.miyobackend.domain.community.entity.read.PostReadModel;
import io.github.herbpot.miyobackend.domain.community.repository.read.EmpathyReadRepository;
import io.github.herbpot.miyobackend.domain.community.repository.read.PostReadRepository;
import io.github.herbpot.miyobackend.domain.community.repository.write.PostRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.locationtech.jts.geom.Point;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * CommentService
 * - 댓글 생성, 삭제 등의 작업 담당
 * - 댓글은 Post 엔티티를 재사용하되, parentPostId를 설정하여 구분
 * - 댓글 작성 시 이미지는 받지 않고, 위치 정보는 부모 게시글로부터 상속
 * - Redis Pub/Sub을 통해 CommentEvent 발행 (CQRS Read Model 업데이트)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CommentService {

    private final PostRepository postRepository;
    private final PostReadRepository postReadRepository;
    private final EmpathyReadRepository empathyReadRepository;
    private final RedisEventPublisher redisEventPublisher;
    private final UserServiceClient userServiceClient;

    /**
     * 댓글 생성
     * 1. 부모 게시글/댓글 존재 여부 확인
     * 2. 부모로부터 위치 정보, 카테고리, 제목 상속
     * 3. User Service에서 사용자 닉네임 조회
     * 4. Post 엔티티 생성 (parentPostId 설정, imagePath는 null)
     * 5. Write DB 저장
     * 6. Redis에 CREATE 이벤트 발행
     * 7. 응답 반환
     *
     * @param request 댓글 생성 요청 (parentPostId, content만 포함)
     * @param userId 작성자 ID (JWT에서 추출)
     * @param token JWT 토큰 (Bearer 토큰 형식)
     * @return 생성된 댓글 정보
     * @throws IllegalArgumentException 부모 게시글/댓글이 존재하지 않는 경우
     */
    @Transactional("writeTransactionManager")
    public PostResponse createComment(CommentCreateRequest request, String userId, String token) {
        log.info("Creating comment: userId={}, parentPostId={}", userId, request.getParentPostId());

        // 1. 부모 게시글/댓글 존재 여부 확인 및 조회
        Post parentPost = postRepository.findById(request.getParentPostId())
                .orElseThrow(() -> {
                    log.warn("Parent post not found: parentPostId={}", request.getParentPostId());
                    return new IllegalArgumentException(
                            "부모 게시글이 존재하지 않습니다. (parentPostId: " + request.getParentPostId() + ")"
                    );
                });

        // 2. 부모로부터 위치 정보, 카테고리, 제목 상속
        Point location = parentPost.getLocation();
        log.info("Inherited from parent post: latitude={}, longitude={}, category={}, title={}",
                location.getY(), location.getX(), parentPost.getCategory(), parentPost.getTitle());

        // 3. User Service에서 사용자 닉네임 조회 (토큰 포함)
        String userNickname = userServiceClient.getUserNickname(userId, token);
        log.info("User nickname fetched: userId={}, nickname={}", userId, userNickname);

        // 4. Post 엔티티 생성 (댓글은 imagePath가 null, 나머지는 부모로부터 상속)
        Post comment = Post.builder()
                .userId(userId)
                .parentPostId(request.getParentPostId())
                .imagePath(null)  // 댓글은 이미지를 받지 않음
                .location(location)  // 부모의 위치 정보 상속
                .category(parentPost.getCategory())  // 부모의 카테고리 상속
                .title(parentPost.getTitle())  // 부모의 제목 상속
                .content(request.getContent())  // 클라이언트에서 전달받은 댓글 내용
                .build();

        // 5. Write DB 저장
        Post savedComment = postRepository.save(comment);
        log.info("Comment saved to write DB: postId={}, parentPostId={}",
                savedComment.getPostId(), savedComment.getParentPostId());

        // 6. Redis 이벤트 발행 (비동기 Read Model 업데이트)
        CommentEvent event = CommentEvent.createEvent(savedComment, userNickname);
        redisEventPublisher.publishCommentEvent(event);

        // 7. 응답 생성 및 반환
        PostResponse response = PostResponse.from(savedComment);
        return PostResponse.builder()
                .postId(response.getPostId())
                .userId(response.getUserId())
                .userNickname(userNickname)
                .parentPostId(response.getParentPostId())
                .imagePath(response.getImagePath())
                .latitude(response.getLatitude())
                .longitude(response.getLongitude())
                .category(response.getCategory())
                .title(response.getTitle())
                .content(response.getContent())
                .createdAt(response.getCreatedAt())
                .build();
    }

    /**
     * 특정 게시글의 댓글 목록 조회 (대댓글 포함)
     * - parentPostId가 일치하는 1단계 댓글들을 페이징하여 조회
     * - 각 댓글의 대댓글(2단계)까지 포함하여 반환
     * - Read DB에서 조회
     * - 공감수 포함하여 반환
     * - 최신순으로 정렬
     *
     * @param parentPostId 부모 게시글 ID
     * @param pageable 페이징 정보
     * @return 댓글 목록 (대댓글 포함, 페이징)
     */
    @Transactional(value = "readTransactionManager", readOnly = true)
    public Page<CommentResponse> getCommentsByPostId(Long parentPostId, Pageable pageable) {
        log.info("Getting comments for post: parentPostId={}, page={}", parentPostId, pageable.getPageNumber());

        // 1단계: parentPostId로 댓글 조회 (Read DB, 페이징)
        Page<PostReadModel> comments = postReadRepository.findByParentPostIdOrderByCreatedAtDesc(parentPostId, pageable);

        log.info("Found {} comments for post {}", comments.getTotalElements(), parentPostId);

        java.util.List<PostReadModel> commentList = comments.getContent();

        if (commentList.isEmpty()) {
            return new org.springframework.data.domain.PageImpl<>(
                    java.util.List.of(),
                    pageable,
                    0
            );
        }

        // 1단계 댓글 ID 리스트 추출
        java.util.List<Long> commentIds = commentList.stream()
                .map(PostReadModel::getPostId)
                .toList();

        // 1단계 댓글 공감수 조회 (한번에 조회)
        java.util.Map<Long, Long> commentEmpathyCountMap = new java.util.HashMap<>();
        if (!commentIds.isEmpty()) {
            java.util.List<Object[]> commentEmpathyCounts = empathyReadRepository.countByPostIds(commentIds);
            for (Object[] row : commentEmpathyCounts) {
                commentEmpathyCountMap.put((Long) row[0], (Long) row[1]);
            }
        }

        // 2단계: 각 1단계 댓글의 대댓글 조회
        java.util.Map<Long, java.util.List<PostReadModel>> repliesMap = new java.util.HashMap<>();
        java.util.List<Long> allReplyIds = new java.util.ArrayList<>();

        for (Long commentId : commentIds) {
            org.springframework.data.domain.Pageable unpaged = org.springframework.data.domain.Pageable.unpaged();
            org.springframework.data.domain.Page<PostReadModel> repliesPage = postReadRepository
                    .findByParentPostIdOrderByCreatedAtDesc(commentId, unpaged);

            java.util.List<PostReadModel> replies = repliesPage.getContent();
            repliesMap.put(commentId, replies);

            // 대댓글 ID 수집
            replies.stream()
                    .map(PostReadModel::getPostId)
                    .forEach(allReplyIds::add);
        }

        // 대댓글 공감수 조회 (한번에 조회)
        java.util.Map<Long, Long> replyEmpathyCountMap = new java.util.HashMap<>();
        if (!allReplyIds.isEmpty()) {
            java.util.List<Object[]> replyEmpathyCounts = empathyReadRepository.countByPostIds(allReplyIds);
            for (Object[] row : replyEmpathyCounts) {
                replyEmpathyCountMap.put((Long) row[0], (Long) row[1]);
            }
        }

        // PostReadModel -> CommentResponse 변환 (대댓글 포함, 최대 2단계)
        java.util.List<CommentResponse> responseList = commentList.stream()
                .map(model -> {
                    CommentResponse comment = CommentResponse.from(
                            model,
                            commentEmpathyCountMap.getOrDefault(model.getPostId(), 0L),
                            false  // 댓글 목록 조회는 인증 없이 가능하므로 공감 여부는 false
                    );

                    // 대댓글 조회 및 설정 (2단계까지만)
                    java.util.List<PostReadModel> replyModels = repliesMap.getOrDefault(model.getPostId(), java.util.List.of());
                    java.util.List<CommentResponse> replies = replyModels.stream()
                            .map(replyModel -> CommentResponse.from(
                                    replyModel,
                                    replyEmpathyCountMap.getOrDefault(replyModel.getPostId(), 0L),
                                    false  // 대댓글도 공감 여부는 false
                            ))
                            .toList();

                    comment.setReplies(replies);
                    return comment;
                })
                .toList();

        // Page 재구성
        return new org.springframework.data.domain.PageImpl<>(
                responseList,
                pageable,
                comments.getTotalElements()
        );
    }
}
