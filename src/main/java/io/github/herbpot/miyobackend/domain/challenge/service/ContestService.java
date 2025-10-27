package io.github.herbpot.miyobackend.domain.challenge.service;

import io.github.herbpot.miyobackend.domain.challenge.dto.ContestResponse;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestData;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestUser;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestUserId;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestDataRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestPostRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

/**
 * ContestService
 * - 공모전 조회, 참가 등의 작업 담당
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ContestService {

    private final ContestDataRepository contestDataRepository;
    private final ContestUserRepository contestUserRepository;
    private final ContestPostRepository contestPostRepository;

    /**
     * 모든 공모전 조회
     *
     * @return 공모전 목록
     */
    @Transactional(readOnly = true)
    public List<ContestResponse> getAllContests() {
        log.info("Getting all contests");
        return contestDataRepository.findAll().stream()
                .map(ContestResponse::from)
                .collect(Collectors.toList());
    }

    /**
     * 진행 중인 공모전 조회
     *
     * @return 진행 중인 공모전 목록
     */
    @Transactional(readOnly = true)
    public List<ContestResponse> getActiveContests() {
        log.info("Getting active contests");
        LocalDate today = LocalDate.now();
        return contestDataRepository.findActiveContests(today).stream()
                .map(contestData -> {
                    Long participantCount = contestUserRepository.countByContestId(contestData.getContestId());
                    Long submissionCount = contestPostRepository.countByContestId(contestData.getContestId());
                    return ContestResponse.withStats(contestData, participantCount, submissionCount);
                })
                .collect(Collectors.toList());
    }

    /**
     * 특정 공모전 상세 조회
     *
     * @param contestId 공모전 ID
     * @param userId 사용자 ID (참가 여부 확인용, Optional)
     * @return 공모전 상세 정보
     */
    @Transactional(readOnly = true)
    public ContestResponse getContestById(Long contestId, String userId) {
        log.info("Getting contest: contestId={}, userId={}", contestId, userId);

        ContestData contestData = contestDataRepository.findById(contestId)
                .orElseThrow(() -> {
                    log.warn("Contest not found: contestId={}", contestId);
                    return new IllegalArgumentException("공모전을 찾을 수 없습니다. (contestId: " + contestId + ")");
                });

        Long participantCount = contestUserRepository.countByContestId(contestId);
        Long submissionCount = contestPostRepository.countByContestId(contestId);

        ContestResponse response = ContestResponse.withStats(contestData, participantCount, submissionCount);

        // 사용자 참가 여부 확인
        if (userId != null) {
            boolean isParticipant = contestUserRepository.existsByContestIdAndUserId(contestId, userId);
            response = ContestResponse.withParticipation(contestData, isParticipant);
            response.setParticipantCount(participantCount);
            response.setSubmissionCount(submissionCount);
        }

        return response;
    }

    /**
     * 공모전 참가
     *
     * @param contestId 공모전 ID
     * @param userId 사용자 ID
     */
    @Transactional
    public void joinContest(Long contestId, String userId) {
        log.info("Joining contest: contestId={}, userId={}", contestId, userId);

        // 공모전 존재 여부 확인
        if (!contestDataRepository.existsById(contestId)) {
            log.warn("Contest not found: contestId={}", contestId);
            throw new IllegalArgumentException("공모전을 찾을 수 없습니다. (contestId: " + contestId + ")");
        }

        // 이미 참가했는지 확인
        ContestUserId id = new ContestUserId(contestId, userId);
        if (contestUserRepository.existsById(id)) {
            log.warn("User already joined contest: contestId={}, userId={}", contestId, userId);
            throw new IllegalArgumentException("이미 참가한 공모전입니다.");
        }

        // 참가 정보 저장
        ContestUser contestUser = ContestUser.of(contestId, userId);
        contestUserRepository.save(contestUser);

        log.info("User joined contest: contestId={}, userId={}", contestId, userId);
    }

    /**
     * 사용자가 참가한 공모전 목록 조회
     *
     * @param userId 사용자 ID
     * @return 참가한 공모전 목록
     */
    @Transactional(readOnly = true)
    public List<ContestResponse> getMyContests(String userId) {
        log.info("Getting user's contests: userId={}", userId);

        List<ContestUser> contestUsers = contestUserRepository.findByUserId(userId);

        return contestUsers.stream()
                .map(contestUser -> {
                    Long contestId = contestUser.getId().getContestId();
                    return contestDataRepository.findById(contestId)
                            .map(contestData -> {
                                Long participantCount = contestUserRepository.countByContestId(contestId);
                                Long submissionCount = contestPostRepository.countByContestId(contestId);
                                ContestResponse response = ContestResponse.withStats(contestData, participantCount, submissionCount);
                                response = ContestResponse.withParticipation(contestData, true);
                                response.setParticipantCount(participantCount);
                                response.setSubmissionCount(submissionCount);
                                return response;
                            })
                            .orElse(null);
                })
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toList());
    }
}
