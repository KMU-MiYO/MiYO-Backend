package io.github.herbpot.miyobackend.domain.challenge.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestCommentEvent;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestEmpathyEvent;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestPostEvent;
import io.github.herbpot.miyobackend.domain.challenge.entity.Mission;
import io.github.herbpot.miyobackend.domain.challenge.entity.UserMissionProgress;
import io.github.herbpot.miyobackend.domain.challenge.repository.MissionRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.UserMissionProgressRepository;
// Community Domain 이벤트 (posts/main 병합 후 활성화)
// import io.github.herbpot.miyobackend.domain.community.dto.CommentEvent;
// import io.github.herbpot.miyobackend.domain.community.dto.EmpathyEvent;
// import io.github.herbpot.miyobackend.domain.community.dto.PostEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

/**
 * MissionEventSubscriber
 * - 6개 이벤트를 구독하여 미션 진행도 자동 업데이트
 * - Community(3) + Challenge(3) 통합 처리
 * - 미션 완료 시 알림 발송 (향후 구현)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MissionEventSubscriber {

    private final ObjectMapper challengeObjectMapper;
    private final MissionRepository missionRepository;
    private final UserMissionProgressRepository userMissionProgressRepository;
    // private final NotificationService notificationService; // 향후 추가

    /**
     * Redis 메시지 수신 핸들러
     * - 6개 이벤트 타입을 구분하여 처리
     */
    public void handleMessage(String message) {
        try {
            log.info("[MissionEventSubscriber] Received message: {}", message);

            // Community Domain 이벤트 처리 (posts/main 병합 후 활성화)
            /*
            // 1️⃣ Community: PostEvent (게시글 생성)
            if (message.contains("\"postId\"") &&
                message.contains("\"parentPostId\":null") &&
                message.contains("\"content\"") &&
                !message.contains("contestId")) {
                PostEvent event = challengeObjectMapper.readValue(message, PostEvent.class);
                handlePostEvent(event);
            }
            // 2️⃣ Community: CommentEvent (댓글 생성)
            else if (message.contains("\"commentId\"") &&
                     message.contains("\"parentPostId\"") &&
                     !message.contains("contestId")) {
                CommentEvent event = challengeObjectMapper.readValue(message, CommentEvent.class);
                handleCommentEvent(event);
            }
            // 3️⃣ Community: EmpathyEvent (공감)
            else if (message.contains("\"empathyId\"") &&
                     !message.contains("contestPostId")) {
                EmpathyEvent event = challengeObjectMapper.readValue(message, EmpathyEvent.class);
                handleEmpathyEvent(event);
            }
            // 4️⃣ Challenge: ContestPostEvent (제출물 생성)
            else */

            // 4️⃣ Challenge: ContestPostEvent (제출물 생성)
            if (message.contains("\"contestPostId\"") &&
                message.contains("\"contestId\"") &&
                message.contains("\"parentPostId\":null")) {
                ContestPostEvent event = challengeObjectMapper.readValue(message, ContestPostEvent.class);
                handleContestPostEvent(event);
            }
            // 5️⃣ Challenge: ContestCommentEvent (댓글 생성)
            else if (message.contains("\"contestPostId\"") &&
                     message.contains("\"parentPostId\"") &&
                     message.contains("\"contestId\"") &&
                     !message.contains("previousEmpathyCount")) {
                ContestCommentEvent event = challengeObjectMapper.readValue(message, ContestCommentEvent.class);
                handleContestCommentEvent(event);
            }
            // 6️⃣ Challenge: ContestEmpathyEvent (공감)
            else if (message.contains("\"contestPostId\"") &&
                     message.contains("\"previousEmpathyCount\"")) {
                ContestEmpathyEvent event = challengeObjectMapper.readValue(message, ContestEmpathyEvent.class);
                handleContestEmpathyEvent(event);
            }
            else {
                log.warn("[MissionEventSubscriber] Unknown message format: {}", message);
            }

        } catch (Exception e) {
            log.error("[MissionEventSubscriber] Failed to handle message: {}",
                    e.getMessage(), e);
        }
    }

    // ========== Community Domain 이벤트 핸들러 (posts/main 병합 후 활성화) ==========

    /*
    @Transactional
    public void handlePostEvent(PostEvent event) {
        if (event.getEventType() == PostEvent.EventType.CREATE) {
            log.info("[Mission] Post created: userId={}, postId={}",
                    event.getUserId(), event.getPostId());
            updateMissionProgress(event.getUserId(), "proposal");
        }
    }

    @Transactional
    public void handleCommentEvent(CommentEvent event) {
        if (event.getEventType() == CommentEvent.EventType.CREATE) {
            log.info("[Mission] Comment created: userId={}, commentId={}",
                    event.getUserId(), event.getCommentId());
            updateMissionProgress(event.getUserId(), "comment");
        }
    }

    @Transactional
    public void handleEmpathyEvent(EmpathyEvent event) {
        if (event.getEventType() == EmpathyEvent.EventType.CREATE) {
            log.info("[Mission] Empathy created: userId={}, empathyId={}",
                    event.getUserId(), event.getEmpathyId());
            updateMissionProgress(event.getUserId(), "empathy");
        }
    }
    */

    // ========== Challenge Domain 이벤트 핸들러 ==========

    /**
     * Challenge: ContestPostEvent 처리
     * - proposal 카테고리 미션 진행도 업데이트
     */
    @Transactional
    public void handleContestPostEvent(ContestPostEvent event) {
        if (event.getEventType() == ContestPostEvent.EventType.CREATE) {
            log.info("[Mission] ContestPost created: userId={}, contestPostId={}",
                    event.getUserId(), event.getContestPostId());
            updateMissionProgress(event.getUserId(), "proposal");
        }
    }

    /**
     * Challenge: ContestCommentEvent 처리
     * - comment 카테고리 미션 진행도 업데이트
     */
    @Transactional
    public void handleContestCommentEvent(ContestCommentEvent event) {
        if (event.getEventType() == ContestCommentEvent.EventType.CREATE) {
            log.info("[Mission] ContestComment created: userId={}, contestPostId={}",
                    event.getUserId(), event.getContestPostId());
            updateMissionProgress(event.getUserId(), "comment");
        }
    }

    /**
     * Challenge: ContestEmpathyEvent 처리
     * - empathy 카테고리 미션 진행도 업데이트
     */
    @Transactional
    public void handleContestEmpathyEvent(ContestEmpathyEvent event) {
        if (event.getEventType() == ContestEmpathyEvent.EventType.CREATE) {
            log.info("[Mission] ContestEmpathy created: userId={}, contestPostId={}",
                    event.getUserId(), event.getContestPostId());
            updateMissionProgress(event.getUserId(), "empathy");
        }
    }

    // ========== 핵심 로직: 미션 진행도 업데이트 ==========

    /**
     * 미션 진행도 업데이트 (핵심 로직)
     * - 현재 활성화된 해당 카테고리의 모든 미션 조회
     * - 사용자의 진행 현황 조회 또는 생성
     * - 진행 횟수 증가
     * - 목표 달성 시 자동 완료 처리
     * - 완료 시 알림 발송 (향후)
     */
    private void updateMissionProgress(String userId, String category) {
        try {
            // 1. 활성화된 해당 카테고리 미션 조회
            List<Mission> activeMissions = missionRepository
                    .findActiveMissionsByCategory(category, LocalDate.now());

            log.info("[Mission] Found {} active missions for category={}",
                    activeMissions.size(), category);

            for (Mission mission : activeMissions) {
                // 2. 사용자 진행 현황 조회 또는 생성
                UserMissionProgress progress = userMissionProgressRepository
                        .findByMissionIdAndUserId(mission.getMissionId(), userId)
                        .orElseGet(() -> {
                            UserMissionProgress newProgress =
                                    UserMissionProgress.createInitial(mission.getMissionId(), userId);
                            return userMissionProgressRepository.save(newProgress);
                        });

                // 3. 이미 완료된 미션은 스킵
                if (progress.getCompleted()) {
                    log.info("[Mission] Already completed: missionId={}, userId={}",
                            mission.getMissionId(), userId);
                    continue;
                }

                // 4. 진행 횟수 증가
                Integer previousCount = progress.getCurrentCount();
                progress.incrementProgress(mission.getGoalCount());
                UserMissionProgress savedProgress = userMissionProgressRepository.save(progress);

                log.info("[Mission] Progress updated: missionId={}, userId={}, " +
                                "currentCount={}/{}, completed={}",
                        mission.getMissionId(), userId,
                        savedProgress.getCurrentCount(), mission.getGoalCount(),
                        savedProgress.getCompleted());

                // 5. 미션 완료 처리
                if (savedProgress.getCompleted() && !previousCount.equals(savedProgress.getCurrentCount())) {
                    handleMissionCompletion(mission, userId);
                }
            }

        } catch (Exception e) {
            log.error("[Mission] Failed to update progress: userId={}, category={}, error={}",
                    userId, category, e.getMessage(), e);
        }
    }

    /**
     * 미션 완료 처리
     * - 리워드 지급 (향후 구현)
     * - 알림 발송 (향후 구현)
     * - 로그 기록
     */
    private void handleMissionCompletion(Mission mission, String userId) {
        log.info("[Mission] 🎉 Mission completed! missionId={}, userId={}, title={}, rewardPoints={}",
                mission.getMissionId(), userId, mission.getTitle(), mission.getRewardPoints());

        // TODO: 리워드 지급
        // rewardService.addReward(userId, mission.getRewardPoints());

        // TODO: 알림 발송
        // notificationService.sendMissionCompletionNotification(userId, mission);

        log.info("[Mission] Mission completion logged: missionId={}, userId={}",
                mission.getMissionId(), userId);
    }
}
