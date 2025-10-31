package io.github.herbpot.miyobackend.domain.challenge.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Challenge Domain Redis Pub/Sub 설정
 * - Contest 제출물/댓글/공감 이벤트 발행을 위한 설정
 * - 3개 토픽: contest-post-events, contest-comment-events, contest-empathy-events
 */
@Configuration
public class ChallengeRedisConfig {

    @Value("${app.redis.topic.contest-post-events:contest-post-events-channel}")
    private String contestPostEventsTopic;

    @Value("${app.redis.topic.contest-comment-events:contest-comment-events-channel}")
    private String contestCommentEventsTopic;

    @Value("${app.redis.topic.contest-empathy-events:contest-empathy-events-channel}")
    private String contestEmpathyEventsTopic;

    @Value("${spring.data.redis.host:localhost}")
    private String host;

    @Value("${spring.data.redis.port:6379}")
    private String port;

    /**
     * ObjectMapper 빈 생성
     * - JavaTimeModule: LocalDateTime 등의 Java 8 날짜/시간 타입 직렬화 지원
     * - WRITE_DATES_AS_TIMESTAMPS 비활성화: ISO-8601 형식으로 날짜 출력
     */
    @Bean(name = "challengeObjectMapper")
    public ObjectMapper challengeObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return mapper;
    }

    /**
     * RedisConnectionFactory
     * - Community Domain과 공유 가능
     * - Lettuce 사용 (Spring Boot 기본)
     */
    @Bean(name = "challengeRedisConnectionFactory")
    public RedisConnectionFactory challengeRedisConnectionFactory() {
        LettuceConnectionFactory factory = new LettuceConnectionFactory(host, Integer.parseInt(port));
        factory.afterPropertiesSet();
        return factory;
    }

    /**
     * RedisTemplate for Event Publishing
     * - Key: String 직렬화
     * - Value: JSON 직렬화 (Jackson)
     */
    @Bean(name = "challengeEventRedisTemplate")
    public RedisTemplate<String, Object> challengeEventRedisTemplate(
            @Qualifier("challengeRedisConnectionFactory") RedisConnectionFactory challengeRedisConnectionFactory,
            @Qualifier("challengeObjectMapper") ObjectMapper challengeObjectMapper) {

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(challengeRedisConnectionFactory);

        // Key Serializer: String
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);

        // Value Serializer: JSON
        Jackson2JsonRedisSerializer<Object> jsonSerializer =
                new Jackson2JsonRedisSerializer<>(challengeObjectMapper, Object.class);
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);

        template.afterPropertiesSet();
        return template;
    }

    /**
     * Redis 채널 토픽 정의 - Contest Post Events
     * - 제출물 생성/삭제 이벤트 발행/구독에 사용되는 채널
     */
    @Bean
    public ChannelTopic contestPostEventsTopic() {
        return new ChannelTopic(contestPostEventsTopic);
    }

    /**
     * Redis 채널 토픽 정의 - Contest Comment Events
     * - 댓글 생성/삭제 이벤트 발행/구독에 사용되는 채널
     */
    @Bean
    public ChannelTopic contestCommentEventsTopic() {
        return new ChannelTopic(contestCommentEventsTopic);
    }

    /**
     * Redis 채널 토픽 정의 - Contest Empathy Events
     * - 공감 추가/취소 이벤트 발행/구독에 사용되는 채널
     */
    @Bean
    public ChannelTopic contestEmpathyEventsTopic() {
        return new ChannelTopic(contestEmpathyEventsTopic);
    }
}
