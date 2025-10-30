package io.github.herbpot.miyobackend.domain.community.service;

import io.github.herbpot.miyobackend.domain.community.dto.CommentEvent;
import io.github.herbpot.miyobackend.domain.community.dto.EmpathyEvent;
import io.github.herbpot.miyobackend.domain.community.dto.Event;
import io.github.herbpot.miyobackend.domain.community.dto.PostEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.stereotype.Service;

/**
 * RedisEventPublisher
 * - Redis Pub/Sub의 Publisher 역할
 * - PostEvent, CommentEvent, EmpathyEvent를 Redis 채널에 발행
 * - Write 작업 후 비동기적으로 Read Model 업데이트를 위한 이벤트 발행
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RedisEventPublisher  {

    private final RedisTemplate<String, Event> redisTemplate;
    private final ChannelTopic postEventsTopic;
    private final ChannelTopic commentEventsTopic;
    private final ChannelTopic empathyEventsTopic;

    /**
     * Event를 Redis 채널에 발행 (통합 메서드)
     * - PostEvent, CommentEvent, EmpathyEvent 타입에 따라 적절한 채널로 발행
     * - Write Model에서 데이터 생성/수정/삭제 후 호출
     * - RedisEventSubscriber가 이 이벤트를 구독하여 Read Model 업데이트
     *
     * @param event 발행할 Event (PostEvent, CommentEvent 또는 EmpathyEvent)
     */
    public void publish(Event event) {
        try {
            if (event instanceof PostEvent postEvent) {
                log.info("Publishing PostEvent to Redis: eventType={}, postId={}",
                        postEvent.getEventType(), postEvent.getPostId());
                redisTemplate.convertAndSend(postEventsTopic.getTopic(), event);
                log.info("Successfully published PostEvent: postId={}", postEvent.getPostId());
            } else if (event instanceof CommentEvent commentEvent) {
                log.info("Publishing CommentEvent to Redis: eventType={}, commentId={}, parentPostId={}",
                        commentEvent.getEventType(), commentEvent.getCommentId(), commentEvent.getParentPostId());
                redisTemplate.convertAndSend(commentEventsTopic.getTopic(), event);
                log.info("Successfully published CommentEvent: commentId={}", commentEvent.getCommentId());
            } else if (event instanceof EmpathyEvent empathyEvent) {
                log.info("Publishing EmpathyEvent to Redis: eventType={}, empathyId={}, postId={}",
                        empathyEvent.getEventType(), empathyEvent.getEmpathyId(), empathyEvent.getPostId());
                redisTemplate.convertAndSend(empathyEventsTopic.getTopic(), event);
                log.info("Successfully published EmpathyEvent: empathyId={}", empathyEvent.getEmpathyId());
            } else {
                log.warn("Unknown event type: {}", event.getClass().getName());
            }
        } catch (Exception e) {
            log.error("Failed to publish Event to Redis: eventType={}, error={}",
                    event.getEventTypeName(), e.getMessage(), e);
            // 예외를 던지지 않고 로그만 남김 (발행 실패가 Write 작업에 영향을 주지 않도록)
            // 실제 프로덕션 환경에서는 재시도 로직이나 Dead Letter Queue 고려 필요
        }
    }

    /**
     * PostEvent를 Redis 채널에 발행
     * - 하위 호환성을 위한 래퍼 메서드
     * @deprecated publish(Event) 메서드 사용 권장
     */
    @Deprecated
    public void publish(PostEvent event) {
        publish((Event) event);
    }

    /**
     * CommentEvent를 Redis 채널에 발행
     * - 명시적 타입 지정을 위한 래퍼 메서드
     */
    public void publishCommentEvent(CommentEvent event) {
        publish((Event) event);
    }

    /**
     * EmpathyEvent를 Redis 채널에 발행
     * - 하위 호환성을 위한 래퍼 메서드
     * @deprecated publish(Event) 메서드 사용 권장
     */
    @Deprecated
    public void publishEmpathyEvent(EmpathyEvent event) {
        publish((Event) event);
    }
}
