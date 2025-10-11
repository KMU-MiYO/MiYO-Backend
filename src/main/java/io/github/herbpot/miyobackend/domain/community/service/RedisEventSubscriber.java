package io.github.herbpot.miyobackend.domain.community.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.herbpot.miyobackend.domain.community.dto.PostEvent;
import io.github.herbpot.miyobackend.domain.community.entity.PostReadModel;
import io.github.herbpot.miyobackend.domain.community.repository.PostReadRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.locationtech.jts.geom.Coordinate;
import org.locationtech.jts.geom.GeometryFactory;
import org.locationtech.jts.geom.Point;
import org.locationtech.jts.geom.PrecisionModel;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * RedisEventSubscriber
 * - Redis Pub/Sub의 Subscriber 역할
 * - Redis 채널에서 PostEvent를 구독하여 Read Model 업데이트
 * - RedisConfig의 MessageListenerAdapter에서 호출됨
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RedisEventSubscriber {

    private final PostReadRepository postReadRepository;
    private final ObjectMapper objectMapper;

    /**
     * GeometryFactory: JTS Point 객체 생성을 위한 팩토리
     * - SRID 4326: WGS84 좌표계 (GPS 표준)
     */
    private static final GeometryFactory GEOMETRY_FACTORY = new GeometryFactory(new PrecisionModel(), 4326);

    /**
     * Redis 메시지 수신 핸들러
     * - RedisConfig의 MessageListenerAdapter가 이 메서드를 호출
     * - JSON 메시지를 PostEvent 객체로 역직렬화
     * - 이벤트 타입에 따라 Read Model 생성 또는 삭제 처리
     *
     * @param message Redis에서 수신한 JSON 메시지
     */
    @Transactional
    public void handleMessage(String message) {
        try {
            log.info("Received Redis message: {}", message);

            // JSON 문자열을 PostEvent 객체로 역직렬화
            PostEvent event = objectMapper.readValue(message, PostEvent.class);

            log.info("Deserialized PostEvent: eventType={}, postId={}",
                    event.getEventType(), event.getPostId());

            // 이벤트 타입에 따라 처리
            switch (event.getEventType()) {
                case CREATE:
                    handleCreateEvent(event);
                    break;
                case DELETE:
                    handleDeleteEvent(event);
                    break;
                default:
                    log.warn("Unknown event type: {}", event.getEventType());
            }

        } catch (Exception e) {
            log.error("Failed to handle Redis message: message={}, error={}",
                    message, e.getMessage(), e);
            // 예외를 던지지 않고 로그만 남김 (구독자 스레드가 죽지 않도록)
            // 실제 프로덕션 환경에서는 Dead Letter Queue나 재시도 메커니즘 고려 필요
        }
    }

    /**
     * CREATE 이벤트 처리
     * - PostEvent의 데이터를 기반으로 PostReadModel 생성
     * - Point 객체 생성: 경도(longitude), 위도(latitude) 순서 주의!
     *
     * @param event CREATE 이벤트
     */
    private void handleCreateEvent(PostEvent event) {
        log.info("Handling CREATE event: postId={}", event.getPostId());

        // Point 객체 생성: Coordinate(X, Y) = Coordinate(경도, 위도)
        Point location = GEOMETRY_FACTORY.createPoint(
                new Coordinate(event.getLongitude(), event.getLatitude())
        );

        // PostReadModel 생성 및 저장
        PostReadModel readModel = PostReadModel.builder()
                .postId(event.getPostId())
                .userId(event.getUserId())
                .parentPostId(event.getParentPostId())
                .imagePath(event.getImagePath())
                .location(location)
                .category(event.getCategory())
                .title(event.getTitle())
                .content(event.getContent())
                .createdAt(event.getCreatedAt())
                .empathyCount(0)
                .build();

        postReadRepository.save(readModel);

        log.info("Successfully created PostReadModel: postId={}", event.getPostId());
    }

    /**
     * DELETE 이벤트 처리
     * - PostReadModel을 하드 삭제
     * - 존재하지 않는 게시글인 경우 경고 로그만 남김
     *
     * @param event DELETE 이벤트
     */
    private void handleDeleteEvent(PostEvent event) {
        log.info("Handling DELETE event: postId={}", event.getPostId());

        postReadRepository.findById(event.getPostId())
                .ifPresentOrElse(
                        readModel -> {
                            postReadRepository.delete(readModel);
                            log.info("Successfully deleted PostReadModel: postId={}", event.getPostId());
                        },
                        () -> log.warn("PostReadModel not found for deletion: postId={}", event.getPostId())
                );
    }
}
