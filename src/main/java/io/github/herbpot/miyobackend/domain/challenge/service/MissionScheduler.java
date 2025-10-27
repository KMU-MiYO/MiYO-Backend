package io.github.herbpot.miyobackend.domain.challenge.service;

import io.github.herbpot.miyobackend.domain.challenge.entity.Mission;
import io.github.herbpot.miyobackend.domain.challenge.repository.MissionRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.UserMissionProgressRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

/**
 * MissionScheduler
 * - 주간/월간 미션 자동 갱신 스케줄러
 * - 매주 일요일 00:00에 주간 미션 리셋
 * - 매월 1일 00:00에 월간 미션 리셋
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MissionScheduler {

    private final MissionRepository missionRepository;
    private final UserMissionProgressRepository userMissionProgressRepository;

    /**
     * 주간 미션 리셋
     * - 매주 일요일 00:00:00에 실행
     * - Cron: 초 분 시 일 월 요일
     */
    @Scheduled(cron = "0 0 0 * * SUN")
    @Transactional
    public void resetWeeklyMissions() {
        log.info("Starting weekly mission reset");

        try {
            LocalDate today = LocalDate.now();

            // 활성화된 주간 미션 조회
            List<Mission> weeklyMissions = missionRepository.findActiveMissionsByPeriodType(
                    Mission.PeriodType.weekly, today
            );

            if (weeklyMissions.isEmpty()) {
                log.info("No active weekly missions to reset");
                return;
            }

            // 미션 ID 목록 추출
            List<Long> missionIds = weeklyMissions.stream()
                    .map(Mission::getMissionId)
                    .collect(Collectors.toList());

            // 모든 사용자의 해당 미션 진행 현황 리셋
            userMissionProgressRepository.resetProgressByMissionIds(missionIds);

            log.info("Weekly missions reset completed: {} missions", missionIds.size());
        } catch (Exception e) {
            log.error("Failed to reset weekly missions", e);
        }
    }

    /**
     * 월간 미션 리셋
     * - 매월 1일 00:00:00에 실행
     * - Cron: 초 분 시 일 월 요일
     */
    @Scheduled(cron = "0 0 0 1 * *")
    @Transactional
    public void resetMonthlyMissions() {
        log.info("Starting monthly mission reset");

        try {
            LocalDate today = LocalDate.now();

            // 활성화된 월간 미션 조회
            List<Mission> monthlyMissions = missionRepository.findActiveMissionsByPeriodType(
                    Mission.PeriodType.monthly, today
            );

            if (monthlyMissions.isEmpty()) {
                log.info("No active monthly missions to reset");
                return;
            }

            // 미션 ID 목록 추출
            List<Long> missionIds = monthlyMissions.stream()
                    .map(Mission::getMissionId)
                    .collect(Collectors.toList());

            // 모든 사용자의 해당 미션 진행 현황 리셋
            userMissionProgressRepository.resetProgressByMissionIds(missionIds);

            log.info("Monthly missions reset completed: {} missions", missionIds.size());
        } catch (Exception e) {
            log.error("Failed to reset monthly missions", e);
        }
    }
}
