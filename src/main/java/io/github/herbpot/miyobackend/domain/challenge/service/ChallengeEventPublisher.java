package io.github.herbpot.miyobackend.domain.challenge.service;

import io.github.herbpot.miyobackend.domain.challenge.dto.ContestCommentEvent;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestEmpathyEvent;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestPostEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.stereotype.Service;

/**
 * ChallengeEventPublisher
 * - Challenge Domain 이벤트를 Redis Pub/Sub으로 발행
 * - 3개 이벤트: ContestPostEvent, ContestCommentEvent, ContestEmpathyEvent
 * - Mission Subscriber가 이를 수신하여 미션 진행도 업데이트
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ChallengeEventPublisher {

    private final RedisTemplate<String, Object> challengeEventRedisTemplate;
    private final ChannelTopic contestPostEventsTopic;
    private final ChannelTopic contestCommentEventsTopic;
    private final ChannelTopic contestEmpathyEventsTopic;

    /**
     * Contest 제출물 생성 이벤트 발행
     */
    public void publishContestPostEvent(ContestPostEvent event) {
        try {
            log.info("[ChallengeEventPublisher] Publishing ContestPostEvent: eventType={}, contestPostId={}, userId={}",
                    event.getEventType(), event.getContestPostId(), event.getUserId());

            challengeEventRedisTemplate.convertAndSend(
                    contestPostEventsTopic.getTopic(), event);

            log.info("[ChallengeEventPublisher] Successfully published ContestPostEvent: contestPostId={}",
                    event.getContestPostId());

        } catch (Exception e) {
            log.error("[ChallengeEventPublisher] Failed to publish ContestPostEvent: contestPostId={}, error={}",
                    event.getContestPostId(), e.getMessage(), e);
            // 발행 실패해도 메인 로직 진행 (로그만 기록)
        }
    }

    /**
     * Contest 댓글 생성 이벤트 발행
     */
    public void publishContestCommentEvent(ContestCommentEvent event) {
        try {
            log.info("[ChallengeEventPublisher] Publishing ContestCommentEvent: eventType={}, contestPostId={}, parentPostId={}, userId={}",
                    event.getEventType(), event.getContestPostId(),
                    event.getParentPostId(), event.getUserId());

            challengeEventRedisTemplate.convertAndSend(
                    contestCommentEventsTopic.getTopic(), event);

            log.info("[ChallengeEventPublisher] Successfully published ContestCommentEvent: contestPostId={}",
                    event.getContestPostId());

        } catch (Exception e) {
            log.error("[ChallengeEventPublisher] Failed to publish ContestCommentEvent: contestPostId={}, error={}",
                    event.getContestPostId(), e.getMessage(), e);
        }
    }

    /**
     * Contest 공감 추가/취소 이벤트 발행
     */
    public void publishContestEmpathyEvent(ContestEmpathyEvent event) {
        try {
            log.info("[ChallengeEventPublisher] Publishing ContestEmpathyEvent: eventType={}, contestPostId={}, userId={}, newCount={}",
                    event.getEventType(), event.getContestPostId(), event.getUserId(), event.getNewEmpathyCount());

            challengeEventRedisTemplate.convertAndSend(
                    contestEmpathyEventsTopic.getTopic(), event);

            log.info("[ChallengeEventPublisher] Successfully published ContestEmpathyEvent: contestPostId={}",
                    event.getContestPostId());

        } catch (Exception e) {
            log.error("[ChallengeEventPublisher] Failed to publish ContestEmpathyEvent: contestPostId={}, error={}",
                    event.getContestPostId(), e.getMessage(), e);
        }
    }
}
