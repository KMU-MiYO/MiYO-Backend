package io.github.herbpot.miyobackend.domain.challenge.service;

import io.github.herbpot.miyobackend.domain.challenge.dto.MissionResponse;
import io.github.herbpot.miyobackend.domain.challenge.dto.UserMissionProgressResponse;
import io.github.herbpot.miyobackend.domain.challenge.entity.Mission;
import io.github.herbpot.miyobackend.domain.challenge.entity.UserMissionProgress;
import io.github.herbpot.miyobackend.domain.challenge.repository.MissionRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.UserMissionProgressRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

/**
 * MissionService
 * - 미션 조회, 진행 현황 관리 등의 작업 담당
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MissionService {

    private final MissionRepository missionRepository;
    private final UserMissionProgressRepository userMissionProgressRepository;

    /**
     * 현재 활성화된 미션 목록 조회
     *
     * @return 활성 미션 목록
     */
    @Transactional(readOnly = true)
    public List<MissionResponse> getActiveMissions() {
        log.info("Getting active missions");
        LocalDate today = LocalDate.now();

        return missionRepository.findActiveMissions(today).stream()
                .map(MissionResponse::from)
                .collect(Collectors.toList());
    }

    /**
     * 특정 기간 타입의 활성 미션 조회
     *
     * @param periodType 기간 타입 (weekly, monthly)
     * @return 활성 미션 목록
     */
    @Transactional(readOnly = true)
    public List<MissionResponse> getActiveMissionsByPeriod(Mission.PeriodType periodType) {
        log.info("Getting active missions by period: periodType={}", periodType);
        LocalDate today = LocalDate.now();

        return missionRepository.findActiveMissionsByPeriodType(periodType, today).stream()
                .map(MissionResponse::from)
                .collect(Collectors.toList());
    }

    /**
     * 사용자의 미션 목록 조회 (진행 현황 포함)
     *
     * @param userId 사용자 ID
     * @return 미션 목록 (진행 현황 포함)
     */
    @Transactional(readOnly = true)
    public List<MissionResponse> getUserMissions(String userId) {
        log.info("Getting user missions: userId={}", userId);
        LocalDate today = LocalDate.now();

        List<Mission> activeMissions = missionRepository.findActiveMissions(today);

        return activeMissions.stream()
                .map(mission -> {
                    UserMissionProgress progress = userMissionProgressRepository
                            .findByMissionIdAndUserId(mission.getMissionId(), userId)
                            .orElse(null);

                    if (progress != null) {
                        return MissionResponse.withProgress(
                                mission,
                                progress.getCurrentCount(),
                                progress.getCompleted()
                        );
                    } else {
                        return MissionResponse.withProgress(mission, 0, false);
                    }
                })
                .collect(Collectors.toList());
    }

    /**
     * 특정 미션 상세 조회
     *
     * @param missionId 미션 ID
     * @return 미션 상세 정보
     */
    @Transactional(readOnly = true)
    public MissionResponse getMissionById(Long missionId) {
        log.info("Getting mission: missionId={}", missionId);

        Mission mission = missionRepository.findById(missionId)
                .orElseThrow(() -> {
                    log.warn("Mission not found: missionId={}", missionId);
                    return new IllegalArgumentException("미션을 찾을 수 없습니다. (missionId: " + missionId + ")");
                });

        return MissionResponse.from(mission);
    }

    /**
     * 사용자의 특정 미션 진행 현황 조회
     *
     * @param missionId 미션 ID
     * @param userId 사용자 ID
     * @return 진행 현황
     */
    @Transactional(readOnly = true)
    public UserMissionProgressResponse getUserMissionProgress(Long missionId, String userId) {
        log.info("Getting user mission progress: missionId={}, userId={}", missionId, userId);

        Mission mission = missionRepository.findById(missionId)
                .orElseThrow(() -> new IllegalArgumentException("미션을 찾을 수 없습니다."));

        UserMissionProgress progress = userMissionProgressRepository
                .findByMissionIdAndUserId(missionId, userId)
                .orElseGet(() -> UserMissionProgress.createInitial(missionId, userId));

        return UserMissionProgressResponse.withMissionInfo(
                progress,
                mission.getTitle(),
                mission.getGoalCount()
        );
    }

    /**
     * 사용자의 모든 미션 진행 현황 조회
     *
     * @param userId 사용자 ID
     * @return 진행 현황 목록
     */
    @Transactional(readOnly = true)
    public List<UserMissionProgressResponse> getAllUserProgress(String userId) {
        log.info("Getting all user progress: userId={}", userId);

        List<UserMissionProgress> progressList = userMissionProgressRepository.findByUserId(userId);

        return progressList.stream()
                .map(progress -> {
                    Mission mission = missionRepository.findById(progress.getMissionId())
                            .orElse(null);

                    if (mission != null) {
                        return UserMissionProgressResponse.withMissionInfo(
                                progress,
                                mission.getTitle(),
                                mission.getGoalCount()
                        );
                    } else {
                        return UserMissionProgressResponse.from(progress);
                    }
                })
                .collect(Collectors.toList());
    }

    /**
     * 사용자의 완료된 미션 목록 조회
     *
     * @param userId 사용자 ID
     * @return 완료된 미션 목록
     */
    @Transactional(readOnly = true)
    public List<UserMissionProgressResponse> getCompletedMissions(String userId) {
        log.info("Getting completed missions: userId={}", userId);

        List<UserMissionProgress> completedList = userMissionProgressRepository.findCompletedMissionsByUserId(userId);

        return completedList.stream()
                .map(progress -> {
                    Mission mission = missionRepository.findById(progress.getMissionId())
                            .orElse(null);

                    if (mission != null) {
                        return UserMissionProgressResponse.withMissionInfo(
                                progress,
                                mission.getTitle(),
                                mission.getGoalCount()
                        );
                    } else {
                        return UserMissionProgressResponse.from(progress);
                    }
                })
                .collect(Collectors.toList());
    }
}
