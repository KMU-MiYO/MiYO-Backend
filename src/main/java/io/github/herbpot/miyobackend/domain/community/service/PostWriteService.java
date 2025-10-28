package io.github.herbpot.miyobackend.domain.community.service;

import io.github.herbpot.miyobackend.client.UserServiceClient;
import io.github.herbpot.miyobackend.domain.community.dto.PostCreateRequest;
import io.github.herbpot.miyobackend.domain.community.dto.PostEvent;
import io.github.herbpot.miyobackend.domain.community.dto.PostResponse;
import io.github.herbpot.miyobackend.domain.community.entity.write.Post;
import io.github.herbpot.miyobackend.domain.community.entity.PostCategory;
import io.github.herbpot.miyobackend.domain.community.repository.write.PostRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.locationtech.jts.geom.Coordinate;
import org.locationtech.jts.geom.GeometryFactory;
import org.locationtech.jts.geom.Point;
import org.locationtech.jts.geom.PrecisionModel;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * PostWriteService
 * - CQRS Write Model 처리 서비스
 * - 게시글 생성, 삭제 등의 쓰기 작업 담당
 * - Write DB에 저장 후 Redis 이벤트 발행
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PostWriteService {

    private final PostRepository postRepository;
    private final RedisEventPublisher redisEventPublisher;
    private final UserServiceClient userServiceClient;

    /**
     * GeometryFactory: JTS Point 객체 생성을 위한 팩토리
     * - SRID 4326: WGS84 좌표계 (GPS 표준)
     */
    private static final GeometryFactory GEOMETRY_FACTORY = new GeometryFactory(new PrecisionModel(), 4326);

    /**
     * 게시글 생성
     * 1. User Service에서 사용자 닉네임 조회
     * 2. Request로부터 Point 객체 생성 (경도, 위도 순서 주의!)
     * 3. Post 엔티티 생성 및 Write DB 저장
     * 4. Redis에 CREATE 이벤트 발행 (비동기 Read Model 업데이트)
     * 5. 응답 반환
     *
     * @param request 게시글 생성 요청
     * @param userId 작성자 ID (JWT에서 추출)
     * @return 생성된 게시글 정보
     */
    @Transactional("writeTransactionManager")
    public PostResponse createPost(PostCreateRequest request, String userId) {
        log.info("Creating post: userId={}, latitude={}, longitude={}",
                userId, request.getLatitude(), request.getLongitude());

        // 1. User Service에서 사용자 닉네임 조회
        String userNickname = userServiceClient.getUserNickname(userId);
        log.info("User nickname fetched: userId={}, nickname={}", userId, userNickname);

        // 2. Point 객체 생성: Coordinate(X, Y) = Coordinate(경도, 위도)
        Point location = GEOMETRY_FACTORY.createPoint(
                new Coordinate(request.getLongitude(), request.getLatitude())
        );

        // 3. Post 엔티티 생성 및 저장
        Post post = Post.builder()
                .userId(userId)
                .parentPostId(null)  // 댓글/답글 API가 분리되어 있으므로 항상 null
                .imagePath(request.getImagePath())
                .location(location)
                .category(request.getCategory())
                .title(request.getTitle())
                .content(request.getContent())
                .build();

        Post savedPost = postRepository.save(post);

        log.info("Post saved to write DB: postId={}", savedPost.getPostId());

        // 4. Redis 이벤트 발행 (비동기 Read Model 업데이트)
        PostEvent event = PostEvent.createEvent(savedPost, userNickname);
        redisEventPublisher.publish(event);

        // 5. 응답 생성 및 반환
        PostResponse response = PostResponse.from(savedPost);
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
     * 게시글/댓글 삭제 (하드 삭제)
     * 1. 게시글/댓글 존재 여부 및 작성자 확인
     * 2. Write DB에서 삭제
     * 3. Redis에 DELETE 이벤트 발행 (비동기 Read Model 업데이트)
     *
     * @param postId 삭제할 게시글/댓글 ID
     * @param userId 요청자 ID (본인 확인용)
     * @throws IllegalArgumentException 게시글/댓글이 존재하지 않거나 작성자가 아닌 경우
     */
    @Transactional("writeTransactionManager")
    public void deletePost(Long postId, String userId) {
        log.info("Deleting post: postId={}, userId={}", postId, userId);

        // 1. 게시글/댓글 조회 및 검증
        Post post = postRepository.findByPostIdAndUserId(postId, userId)
                .orElseThrow(() -> {
                    log.warn("Post not found or unauthorized: postId={}, userId={}", postId, userId);
                    return new IllegalArgumentException(
                            "게시글이 존재하지 않거나 삭제 권한이 없습니다. (postId: " + postId + ")"
                    );
                });

        // 2. 하드 삭제
        postRepository.delete(post);

        log.info("Post deleted in write DB: postId={}", postId);

        // 3. Redis 이벤트 발행 (비동기 Read Model 업데이트)
        PostEvent event = PostEvent.deleteEvent(postId);
        redisEventPublisher.publish(event);
    }
}
