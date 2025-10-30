package io.github.herbpot.miyobackend.domain.challenge.config;

import io.github.herbpot.miyobackend.domain.challenge.service.MissionEventSubscriber;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;

/**
 * Mission Event Subscriber 설정
 * - 6개 토픽을 모두 구독:
 *   [Community Domain - posts/main]
 *   1. post-events-channel (게시글)
 *   2. comment-events-channel (댓글)
 *   3. empathy-events-channel (공감)
 *   [Challenge Domain - challenge/main]
 *   4. contest-post-events-channel (제출물)
 *   5. contest-comment-events-channel (댓글)
 *   6. contest-empathy-events-channel (공감)
 * - 이벤트 수신 시 미션 진행도 자동 업데이트
 */
@Configuration
public class MissionRedisConfig {

    /**
     * Mission Event Subscriber를 위한 MessageListenerAdapter
     * - MissionEventSubscriber의 handleMessage() 메서드 호출
     */
    @Bean
    public MessageListenerAdapter missionMessageListenerAdapter(MissionEventSubscriber subscriber) {
        return new MessageListenerAdapter(subscriber, "handleMessage");
    }

    /**
     * Mission Event Subscriber Container
     * - 6개 토픽 모두 구독
     * - Community Domain 토픽 (postEventsTopic, commentEventsTopic, empathyEventsTopic)은
     *   posts/main의 RedisConfig에서 정의됨 (통합 시 사용)
     * - Challenge Domain 토픽 (contestPostEventsTopic, contestCommentEventsTopic, contestEmpathyEventsTopic)은
     *   ChallengeRedisConfig에서 정의됨
     */
    @Bean
    public RedisMessageListenerContainer missionRedisMessageListenerContainer(
            RedisConnectionFactory challengeRedisConnectionFactory,
            MessageListenerAdapter missionMessageListenerAdapter,
            // Challenge Domain 토픽 (현재 브랜치에서 사용 가능)
            ChannelTopic contestPostEventsTopic,
            ChannelTopic contestCommentEventsTopic,
            ChannelTopic contestEmpathyEventsTopic
            // Community Domain 토픽 (posts/main 병합 후 활성화)
            // ChannelTopic postEventsTopic,
            // ChannelTopic commentEventsTopic,
            // ChannelTopic empathyEventsTopic
    ) {

        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(challengeRedisConnectionFactory);

        // Challenge Domain 3개 토픽 구독
        container.addMessageListener(missionMessageListenerAdapter, contestPostEventsTopic);
        container.addMessageListener(missionMessageListenerAdapter, contestCommentEventsTopic);
        container.addMessageListener(missionMessageListenerAdapter, contestEmpathyEventsTopic);

        // Community Domain 3개 토픽 구독 (posts/main 병합 후 주석 해제)
        // container.addMessageListener(missionMessageListenerAdapter, postEventsTopic);
        // container.addMessageListener(missionMessageListenerAdapter, commentEventsTopic);
        // container.addMessageListener(missionMessageListenerAdapter, empathyEventsTopic);

        return container;
    }
}
