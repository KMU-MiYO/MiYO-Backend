package io.github.herbpot.miyobackend.domain.community.validator;

import io.github.herbpot.miyobackend.domain.community.entity.mission.Mission;
import io.github.herbpot.miyobackend.domain.community.entity.mission.UserMissionProgress;
import io.github.herbpot.miyobackend.domain.community.repository.mission.MissionRepository;
import io.github.herbpot.miyobackend.domain.community.repository.mission.UserMissionProgressRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

/**
 * ProposalMissionValidator
 * - 제안서(게시글) 작성 미션 검증 및 진행도 업데이트
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ProposalMissionValidator implements MissionValidator {

    private final MissionRepository missionRepository;
    private final UserMissionProgressRepository userMissionProgressRepository;

    @Override
    public String getCategory() {
        return "proposal";
    }

    @Override
    @Transactional("writeTransactionManager")
    public void validateAndUpdateProgress(String userId, Long relatedId) {
        log.info("Validating proposal mission: userId={}, postId={}", userId, relatedId);

        // 1. 현재 활성화된 "proposal" 카테고리 미션 조회
        LocalDate today = LocalDate.now();
        List<Mission> activeMissions = missionRepository.findActiveMissionsByCategory("proposal", today);

        if (activeMissions.isEmpty()) {
            log.debug("No active proposal missions found");
            return;
        }

        // 2. 각 미션에 대해 진행도 업데이트
        for (Mission mission : activeMissions) {
            // 유저의 진행도 조회 또는 생성
            UserMissionProgress progress = userMissionProgressRepository
                    .findByMissionIdAndUserId(mission.getMissionId(), userId)
                    .orElseGet(() -> {
                        log.info("Creating new progress for userId={}, missionId={}", userId, mission.getMissionId());
                        UserMissionProgress newProgress = UserMissionProgress.createInitial(mission.getMissionId(), userId);
                        return userMissionProgressRepository.save(newProgress);
                    });

            // 진행도 증가
            progress.incrementProgress(mission.getGoalCount());
            userMissionProgressRepository.save(progress);

            log.info("Proposal mission progress updated: userId={}, missionId={}, currentCount={}, completed={}",
                    userId, mission.getMissionId(), progress.getCurrentCount(), progress.getCompleted());
        }
    }
}
