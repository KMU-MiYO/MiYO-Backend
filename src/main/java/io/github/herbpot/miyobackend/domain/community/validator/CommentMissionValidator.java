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
 * CommentMissionValidator
 * - 댓글 작성 미션 검증 및 진행도 업데이트
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CommentMissionValidator implements MissionValidator {

    private final MissionRepository missionRepository;
    private final UserMissionProgressRepository userMissionProgressRepository;

    @Override
    public String getCategory() {
        return "comment";
    }

    @Override
    @Transactional("writeTransactionManager")
    public void validateAndUpdateProgress(String userId, Long relatedId) {
        log.info("Validating comment mission: userId={}, commentId={}", userId, relatedId);

        LocalDate today = LocalDate.now();
        List<Mission> activeMissions = missionRepository.findActiveMissionsByCategory("comment", today);

        if (activeMissions.isEmpty()) {
            log.debug("No active comment missions found");
            return;
        }

        for (Mission mission : activeMissions) {
            UserMissionProgress progress = userMissionProgressRepository
                    .findByMissionIdAndUserId(mission.getMissionId(), userId)
                    .orElseGet(() -> {
                        log.info("Creating new progress for userId={}, missionId={}", userId, mission.getMissionId());
                        UserMissionProgress newProgress = UserMissionProgress.createInitial(mission.getMissionId(), userId);
                        return userMissionProgressRepository.save(newProgress);
                    });

            progress.incrementProgress(mission.getGoalCount());
            userMissionProgressRepository.save(progress);

            log.info("Comment mission progress updated: userId={}, missionId={}, currentCount={}, completed={}",
                    userId, mission.getMissionId(), progress.getCurrentCount(), progress.getCompleted());
        }
    }
}
