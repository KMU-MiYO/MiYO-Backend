package io.github.herbpot.miyobackend.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.herbpot.miyobackend.domain.community.dto.PostEvent;
import io.github.herbpot.miyobackend.domain.community.service.RedisEventSubscriber;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Redis 설정 클래스
 * - Redis Pub/Sub을 활용한 CQRS 이벤트 처리
 * - PostEvent 직렬화/역직렬화 설정
 * - 메시지 리스너 컨테이너 구성
 */
@Configuration
public class RedisConfig {

    /**
     * Redis 토픽 이름 (application.properties에서 주입)
     */
    @Value("${app.redis.topic.post-events:post-events-channel}")
    private String postEventsTopic;

    @Value("${spring.data.redis.host}")
    private String host;

    @Value("${spring.data.redis.port}")
    private String port;


    /**
     * ObjectMapper 빈 생성
     * - JavaTimeModule: LocalDateTime 등의 Java 8 날짜/시간 타입 직렬화 지원
     * - WRITE_DATES_AS_TIMESTAMPS 비활성화: ISO-8601 형식으로 날짜 출력
     */
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return mapper;
    }


    @Bean
    public RedisConnectionFactory redisConnectionFactory(){
        LettuceConnectionFactory factory = new LettuceConnectionFactory(host, Integer.parseInt(port));
        factory.afterPropertiesSet();
        return factory;
    }

    /**
     * RedisTemplate 설정
     * - Key: String 직렬화
     * - Value: Jackson JSON 직렬화 (PostEvent 객체 처리)
     */
    @Bean
    public RedisTemplate<String, PostEvent> redisTemplate(
            ObjectMapper objectMapper) {

        RedisTemplate<String, PostEvent> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory());
        // Key Serializer: String
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);

        // Value Serializer: JSON (PostEvent 객체를 JSON으로 변환)
        Jackson2JsonRedisSerializer<PostEvent> jsonSerializer =
            new Jackson2JsonRedisSerializer<>(objectMapper, PostEvent.class);
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);

        template.afterPropertiesSet();
        return template;
    }

    /**
     * Redis 채널 토픽 정의
     * - 게시글 이벤트 발행/구독에 사용되는 채널
     */
    @Bean
    public ChannelTopic postEventsTopic() {
        return new ChannelTopic(postEventsTopic);
    }

    /**
     * MessageListenerAdapter 설정
     * - Redis 메시지를 수신하여 RedisEventSubscriber의 handleMessage 메서드 호출
     */
    @Bean
    public MessageListenerAdapter messageListenerAdapter(RedisEventSubscriber subscriber) {
        return new MessageListenerAdapter(subscriber, "handleMessage");
    }

    /**
     * RedisMessageListenerContainer 설정
     * - Redis Pub/Sub 메시지 리스너 컨테이너
     * - 지정된 채널(postEventsTopic)을 구독하고, 메시지를 MessageListenerAdapter로 전달
     * - 비동기적으로 메시지를 수신 처리
     */
    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
            MessageListenerAdapter messageListenerAdapter,
            ChannelTopic postEventsTopic) {

        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(redisConnectionFactory());

        // 채널 토픽에 메시지 리스너 등록
        container.addMessageListener(messageListenerAdapter, postEventsTopic);

        return container;
    }
}
