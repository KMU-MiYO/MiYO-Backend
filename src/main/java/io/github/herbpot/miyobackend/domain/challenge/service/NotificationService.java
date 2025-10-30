package io.github.herbpot.miyobackend.domain.challenge.service;

import io.github.herbpot.miyobackend.domain.challenge.entity.Mission;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * NotificationService
 * - 미션 완료 알림 발송
 * - 푸시 알림 / 이메일 / SMS 등
 * - 향후 구현 예정
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    /**
     * 미션 완료 알림 발송
     *
     * @param userId 사용자 ID
     * @param mission 완료된 미션
     */
    public void sendMissionCompletionNotification(String userId, Mission mission) {
        log.info("[Notification] Sending mission completion notification: " +
                        "userId={}, missionId={}, title={}, rewardPoints={}",
                userId, mission.getMissionId(), mission.getTitle(), mission.getRewardPoints());

        // TODO: 실제 알림 발송 구현
        // - FCM (Firebase Cloud Messaging) for 푸시 알림
        // - SMTP for 이메일
        // - SMS API for 문자

        // 예시 메시지:
        // "🎉 축하합니다! '{mission.getTitle()}' 미션을 완료했습니다!
        //  리워드 {mission.getRewardPoints()}P를 획득했습니다!"

        log.info("[Notification] Mission completion notification logged: " +
                        "userId={}, missionId={}",
                userId, mission.getMissionId());
    }

    /**
     * 미션 진행 상황 알림
     * - 예: 50%, 75% 달성 시 알림
     *
     * @param userId 사용자 ID
     * @param mission 진행 중인 미션
     * @param currentCount 현재 진행 횟수
     * @param goalCount 목표 횟수
     */
    public void sendMissionProgressNotification(String userId, Mission mission,
                                                 Integer currentCount, Integer goalCount) {
        log.info("[Notification] Sending mission progress notification: " +
                        "userId={}, missionId={}, progress={}/{}",
                userId, mission.getMissionId(), currentCount, goalCount);

        // TODO: 실제 알림 발송 구현
        // 예시: 50%, 75% 달성 시 알림
        // "'{mission.getTitle()}' 미션이 {currentCount}/{goalCount} 진행 중입니다!"

        double progressRate = (double) currentCount / goalCount;
        if (progressRate == 0.5 || progressRate == 0.75) {
            log.info("[Notification] Milestone reached: {}% for missionId={}",
                    (int) (progressRate * 100), mission.getMissionId());
        }
    }

    /**
     * 주간/월간 미션 리셋 알림
     * - 스케줄러에서 호출
     *
     * @param userId 사용자 ID
     * @param periodType 기간 타입 (weekly/monthly)
     */
    public void sendMissionResetNotification(String userId, Mission.PeriodType periodType) {
        log.info("[Notification] Sending mission reset notification: " +
                        "userId={}, periodType={}",
                userId, periodType);

        // TODO: 실제 알림 발송 구현
        // "새로운 {periodType} 미션이 시작되었습니다! 지금 확인해보세요!"
    }
}
