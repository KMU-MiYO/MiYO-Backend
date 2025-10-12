package io.github.herbpot.miyobackend.domain.community.service;

import io.github.herbpot.miyobackend.domain.community.dto.PostEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.stereotype.Service;

/**
 * RedisEventPublisher
 * - Redis Pub/Sub의 Publisher 역할
 * - PostEvent를 Redis 채널에 발행
 * - Write 작업 후 비동기적으로 Read Model 업데이트를 위한 이벤트 발행
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RedisEventPublisher {

    private final RedisTemplate<String, PostEvent> redisTemplate;
    private final ChannelTopic postEventsTopic;

    /**
     * PostEvent를 Redis 채널에 발행
     * - Write Model에서 게시글 생성/삭제 후 호출
     * - RedisEventSubscriber가 이 이벤트를 구독하여 Read Model 업데이트
     *
     * @param event 발행할 PostEvent (CREATE 또는 DELETE)
     */
    public void publish(PostEvent event) {
        try {
            log.info("Publishing PostEvent to Redis: eventType={}, postId={}",
                    event.getEventType(), event.getPostId());

            // Redis 채널에 이벤트 발행
            redisTemplate.convertAndSend(postEventsTopic.getTopic(), event);

            log.info("Successfully published PostEvent: postId={}", event.getPostId());
        } catch (Exception e) {
            log.error("Failed to publish PostEvent to Redis: postId={}, error={}",
                    event.getPostId(), e.getMessage(), e);
            // 예외를 던지지 않고 로그만 남김 (발행 실패가 Write 작업에 영향을 주지 않도록)
            // 실제 프로덕션 환경에서는 재시도 로직이나 Dead Letter Queue 고려 필요
        }
    }
}
