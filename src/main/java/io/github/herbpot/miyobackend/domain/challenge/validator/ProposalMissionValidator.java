package io.github.herbpot.miyobackend.domain.challenge.validator;

import io.github.herbpot.miyobackend.domain.challenge.entity.Mission;
import io.github.herbpot.miyobackend.domain.challenge.entity.UserMissionProgress;
import io.github.herbpot.miyobackend.domain.challenge.repository.MissionRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.UserMissionProgressRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

/**
 * ProposalMissionValidator
 * - 제안(제출물 작성) 미션 검증자
 * - 공모전 제출물을 작성할 때마다 진행도 업데이트
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ProposalMissionValidator implements MissionValidator {

    private final MissionRepository missionRepository;
    private final UserMissionProgressRepository userMissionProgressRepository;

    private static final String CATEGORY = "proposal";

    @Override
    public String getCategory() {
        return CATEGORY;
    }

    @Override
    @Transactional
    public void validateAndUpdateProgress(String userId, Long relatedId) {
        log.info("Validating proposal mission for userId: {}, contestPostId: {}", userId, relatedId);

        // 현재 활성화된 제안 미션 조회
        List<Mission> activeMissions = missionRepository.findActiveMissionsByCategory(CATEGORY, LocalDate.now());

        for (Mission mission : activeMissions) {
            // 사용자의 미션 진행 현황 조회 또는 생성
            UserMissionProgress progress = userMissionProgressRepository
                    .findByMissionIdAndUserId(mission.getMissionId(), userId)
                    .orElseGet(() -> {
                        UserMissionProgress newProgress = UserMissionProgress.createInitial(mission.getMissionId(), userId);
                        return userMissionProgressRepository.save(newProgress);
                    });

            // 이미 완료된 미션이면 스킵
            if (progress.getCompleted()) {
                log.debug("Mission already completed: missionId={}, userId={}", mission.getMissionId(), userId);
                continue;
            }

            // 진행도 업데이트
            progress.incrementProgress(mission.getGoalCount());
            userMissionProgressRepository.save(progress);

            log.info("Updated proposal mission progress: missionId={}, userId={}, currentCount={}/{}, completed={}",
                    mission.getMissionId(), userId, progress.getCurrentCount(), mission.getGoalCount(), progress.getCompleted());
        }
    }
}
