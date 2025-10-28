package io.github.herbpot.miyobackend.domain.community.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.herbpot.miyobackend.domain.community.dto.EmpathyEvent;
import io.github.herbpot.miyobackend.domain.community.dto.PostEvent;
import io.github.herbpot.miyobackend.domain.community.entity.read.EmpathyReadModel;
import io.github.herbpot.miyobackend.domain.community.entity.read.PostReadModel;
import io.github.herbpot.miyobackend.domain.community.repository.read.EmpathyReadRepository;
import io.github.herbpot.miyobackend.domain.community.repository.read.PostReadRepository;
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
 * - Redis 채널에서 PostEvent, EmpathyEvent를 구독하여 Read Model 업데이트
 * - RedisConfig의 MessageListenerAdapter에서 호출됨
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RedisEventSubscriber {

    private final PostReadRepository postReadRepository;
    private final EmpathyReadRepository empathyReadRepository;
    private final ObjectMapper objectMapper;

    /**
     * GeometryFactory: JTS Point 객체 생성을 위한 팩토리
     * - SRID 4326: WGS84 좌표계 (GPS 표준)
     */
    private static final GeometryFactory GEOMETRY_FACTORY = new GeometryFactory(new PrecisionModel(), 4326);

    /**
     * Redis 메시지 수신 핸들러
     * - RedisConfig의 MessageListenerAdapter가 이 메서드를 호출
     * - JSON 메시지를 PostEvent 또는 EmpathyEvent 객체로 역직렬화
     * - 이벤트 타입에 따라 Read Model 생성 또는 삭제 처리
     *
     * @param message Redis에서 수신한 JSON 메시지
     */
    @Transactional("readTransactionManager")
    public void handleMessage(String message) {
        try {
            log.info("Received Redis message: {}", message);

            // 먼저 PostEvent로 시도
            if (message.contains("\"postId\"") && message.contains("\"content\"")) {
                PostEvent event = objectMapper.readValue(message, PostEvent.class);
                log.info("Deserialized PostEvent: eventType={}, postId={}",
                        event.getEventType(), event.getPostId());
                handlePostEvent(event);
            }
            // EmpathyEvent로 시도
            else if (message.contains("\"empathyId\"")) {
                EmpathyEvent event = objectMapper.readValue(message, EmpathyEvent.class);
                log.info("Deserialized EmpathyEvent: eventType={}, empathyId={}, postId={}",
                        event.getEventType(), event.getEmpathyId(), event.getPostId());
                handleEmpathyEvent(event);
            }
            else {
                log.warn("Unknown message format: {}", message);
            }

        } catch (Exception e) {
            log.error("Failed to handle Redis message: message={}, error={}",
                    message, e.getMessage(), e);
            // 예외를 던지지 않고 로그만 남김 (구독자 스레드가 죽지 않도록)
            // 실제 프로덕션 환경에서는 Dead Letter Queue나 재시도 메커니즘 고려 필요
        }
    }

    /**
     * PostEvent 처리
     */
    private void handlePostEvent(PostEvent event) {
        switch (event.getEventType()) {
            case CREATE:
                handleCreateEvent(event);
                break;
            case UPDATE:
                handleUpdateEvent(event);
                break;
            case DELETE:
                handleDeleteEvent(event);
                break;
            default:
                log.warn("Unknown PostEvent type: {}", event.getEventType());
        }
    }

    /**
     * EmpathyEvent 처리
     */
    private void handleEmpathyEvent(EmpathyEvent event) {
        switch (event.getEventType()) {
            case CREATE:
                handleEmpathyCreateEvent(event);
                break;
            case DELETE:
                handleEmpathyDeleteEvent(event);
                break;
            default:
                log.warn("Unknown EmpathyEvent type: {}", event.getEventType());
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
                .userNickname(event.getUserNickname())
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
     * UPDATE 이벤트 처리
     * - PostReadModel의 userId와 userNickname 업데이트 (논리 삭제 시 사용)
     * - 존재하지 않는 게시글인 경우 경고 로그만 남김
     *
     * @param event UPDATE 이벤트
     */
    private void handleUpdateEvent(PostEvent event) {
        log.info("Handling UPDATE event: postId={}", event.getPostId());

        postReadRepository.findById(event.getPostId())
                .ifPresentOrElse(
                        readModel -> {
                            // Point 객체 생성
                            Point location = GEOMETRY_FACTORY.createPoint(
                                    new Coordinate(event.getLongitude(), event.getLatitude())
                            );

                            // 전체 필드 업데이트
                            PostReadModel updatedModel = PostReadModel.builder()
                                    .postId(event.getPostId())
                                    .userId(event.getUserId())
                                    .userNickname(event.getUserNickname())
                                    .parentPostId(event.getParentPostId())
                                    .imagePath(event.getImagePath())
                                    .location(location)
                                    .category(event.getCategory())
                                    .title(event.getTitle())
                                    .content(event.getContent())
                                    .createdAt(event.getCreatedAt())
                                    .empathyCount(readModel.getEmpathyCount())  // 기존 공감수 유지
                                    .build();

                            postReadRepository.save(updatedModel);
                            log.info("Successfully updated PostReadModel: postId={}, userId={}",
                                    event.getPostId(), event.getUserId());
                        },
                        () -> log.warn("PostReadModel not found for update: postId={}", event.getPostId())
                );
    }

    /**
     * DELETE 이벤트 처리 (하드 삭제 시 사용, 현재 미사용)
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

    /**
     * EmpathyEvent CREATE 처리
     * - EmpathyReadModel 생성 및 저장
     *
     * @param event Empathy CREATE 이벤트
     */
    private void handleEmpathyCreateEvent(EmpathyEvent event) {
        log.info("Handling Empathy CREATE event: empathyId={}, postId={}",
                event.getEmpathyId(), event.getPostId());

        EmpathyReadModel readModel = EmpathyReadModel.builder()
                .empathyId(event.getEmpathyId())
                .userId(event.getUserId())
                .postId(event.getPostId())
                .createdAt(event.getCreatedAt())
                .build();

        empathyReadRepository.save(readModel);

        log.info("Successfully created EmpathyReadModel: empathyId={}", event.getEmpathyId());
    }

    /**
     * EmpathyEvent DELETE 처리
     * - EmpathyReadModel 삭제
     *
     * @param event Empathy DELETE 이벤트
     */
    private void handleEmpathyDeleteEvent(EmpathyEvent event) {
        log.info("Handling Empathy DELETE event: empathyId={}, postId={}",
                event.getEmpathyId(), event.getPostId());

        empathyReadRepository.findById(event.getEmpathyId())
                .ifPresentOrElse(
                        readModel -> {
                            empathyReadRepository.delete(readModel);
                            log.info("Successfully deleted EmpathyReadModel: empathyId={}", event.getEmpathyId());
                        },
                        () -> log.warn("EmpathyReadModel not found for deletion: empathyId={}", event.getEmpathyId())
                );
    }
}
