package io.github.herbpot.miyobackend.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.herbpot.miyobackend.domain.community.dto.Event;
import io.github.herbpot.miyobackend.domain.community.service.RedisEventSubscriber;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
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
@EnableRedisRepositories(basePackages = "io.github.herbpot.miyobackend.redis.repository")
public class RedisConfig {

    /**
     * Redis 토픽 이름 (application.properties에서 주입)
     */
    @Value("${app.redis.topic.post-events:post-events-channel}")
    private String postEventsTopic;

    @Value("${app.redis.topic.empathy-events:empathy-events-channel}")
    private String empathyEventsTopic;

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
     * - Value: Jackson JSON 직렬화 (Event 인터페이스로 PostEvent, EmpathyEvent 모두 처리)
     */
    @Bean
    public RedisTemplate<String, Event> redisTemplate(
            RedisConnectionFactory connectionFactory,
            ObjectMapper objectMapper) {

        RedisTemplate<String, Event> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        // Key Serializer: String
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);

        // Value Serializer: JSON (Event 인터페이스로 PostEvent, EmpathyEvent 모두 처리)
        Jackson2JsonRedisSerializer<Event> jsonSerializer =
            new Jackson2JsonRedisSerializer<>(objectMapper, Event.class);
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);

        template.afterPropertiesSet();
        return template;
    }

    /**
     * Redis 채널 토픽 정의 - Post Events
     * - 게시글 이벤트 발행/구독에 사용되는 채널
     */
    @Bean
    public ChannelTopic postEventsTopic() {
        return new ChannelTopic(postEventsTopic);
    }

    /**
     * Redis 채널 토픽 정의 - Empathy Events
     * - 공감 이벤트 발행/구독에 사용되는 채널
     */
    @Bean
    public ChannelTopic empathyEventsTopic() {
        return new ChannelTopic(empathyEventsTopic);
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
     * - postEventsTopic, empathyEventsTopic 모두 구독
     * - 비동기적으로 메시지를 수신 처리
     */
    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
            RedisConnectionFactory connectionFactory,
            MessageListenerAdapter messageListenerAdapter,
            ChannelTopic postEventsTopic,
            ChannelTopic empathyEventsTopic) {

        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);

        // 두 채널 토픽 모두에 메시지 리스너 등록
        container.addMessageListener(messageListenerAdapter, postEventsTopic);
        container.addMessageListener(messageListenerAdapter, empathyEventsTopic);

        return container;
    }
}
