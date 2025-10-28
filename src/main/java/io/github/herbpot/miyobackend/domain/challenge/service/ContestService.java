package io.github.herbpot.miyobackend.domain.challenge.service;

import io.github.herbpot.miyobackend.domain.challenge.dto.ContestCreateRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestListResponse;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestPostSummaryResponse;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestResponse;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestData;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestUser;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestUserId;
import io.github.herbpot.miyobackend.domain.challenge.exception.AlreadyJoinedException;
import io.github.herbpot.miyobackend.domain.challenge.exception.ContestNotFoundException;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestDataRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestPostRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
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
     * 진행 중인 공모전 목록 조회 (최소 정보)
     * - contestId, title, host, category만 반환
     *
     * @return 진행 중인 공모전 목록
     */
    @Transactional(readOnly = true)
    public List<ContestListResponse> getActiveContestsList() {
        log.info("Getting active contests list");
        LocalDate today = LocalDate.now();
        return contestDataRepository.findActiveContests(today).stream()
                .map(ContestListResponse::from)
                .collect(Collectors.toList());
    }

    /**
     * 진행 중인 공모전 조회 (상세 정보)
     * @deprecated Use getActiveContestsList() for list view
     *
     * @return 진행 중인 공모전 목록
     */
    @Deprecated
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
     * @return 공모전 상세 정보 (Top 3 인기 제안 포함)
     */
    @Transactional(readOnly = true)
    public ContestResponse getContestById(Long contestId, String userId) {
        log.info("Getting contest: contestId={}, userId={}", contestId, userId);

        ContestData contestData = contestDataRepository.findById(contestId)
                .orElseThrow(() -> new ContestNotFoundException(contestId));

        Long participantCount = contestUserRepository.countByContestId(contestId);
        Long submissionCount = contestPostRepository.countByContestId(contestId);

        // Top 3 인기 제안 조회 (공감 수 기준)
        List<ContestPostSummaryResponse> topPosts = contestPostRepository
                .findTopByContestIdOrderByEmpathy(contestId, PageRequest.of(0, 3))
                .stream()
                .map(ContestPostSummaryResponse::from)
                .collect(Collectors.toList());

        ContestResponse response = ContestResponse.withStats(contestData, participantCount, submissionCount);
        response.setTopPosts(topPosts);

        // 사용자 참가 여부 확인
        if (userId != null) {
            boolean isParticipant = contestUserRepository.existsByContestIdAndUserId(contestId, userId);
            response = ContestResponse.withParticipation(contestData, isParticipant);
            response.setParticipantCount(participantCount);
            response.setSubmissionCount(submissionCount);
            response.setTopPosts(topPosts);
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
            throw new ContestNotFoundException(contestId);
        }

        // 이미 참가했는지 확인
        ContestUserId id = new ContestUserId(contestId, userId);
        if (contestUserRepository.existsById(id)) {
            log.warn("User already joined contest: contestId={}, userId={}", contestId, userId);
            throw new AlreadyJoinedException(contestId, userId);
        }

        // 참가 정보 저장
        ContestUser contestUser = ContestUser.of(contestId, userId);
        contestUserRepository.save(contestUser);

        log.info("User joined contest: contestId={}, userId={}", contestId, userId);
    }

    /**
     * 사용자가 참가한 공모전 목록 조회 (최소 정보)
     * - contestId, title, host, category만 반환
     *
     * @param userId 사용자 ID
     * @return 참가한 공모전 목록
     */
    @Transactional(readOnly = true)
    public List<ContestListResponse> getMyContestsList(String userId) {
        log.info("Getting user's contests list: userId={}", userId);

        List<ContestUser> contestUsers = contestUserRepository.findByUserId(userId);

        return contestUsers.stream()
                .map(contestUser -> {
                    Long contestId = contestUser.getId().getContestId();
                    return contestDataRepository.findById(contestId)
                            .map(ContestListResponse::from)
                            .orElse(null);
                })
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toList());
    }

    /**
     * 사용자가 참가한 공모전 목록 조회 (상세 정보)
     * @deprecated Use getMyContestsList() for list view
     *
     * @param userId 사용자 ID
     * @return 참가한 공모전 목록
     */
    @Deprecated
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

    /**
     * 공모전 생성 (관리자 전용)
     *
     * @param request 공모전 생성 요청
     * @return 생성된 공모전 정보
     */
    @Transactional
    public ContestResponse createContest(ContestCreateRequest request) {
        log.info("Creating contest: title={}", request.getTitle());

        // ContestData 엔티티 생성
        ContestData contestData = ContestData.builder()
                .title(request.getTitle())
                .host(request.getHost())
                .category(request.getCategory())
                .description(request.getDescription())
                .startDate(request.getStartDate())
                .endDate(request.getEndDate())
                .reward1st(request.getReward1st())
                .reward2nd(request.getReward2nd())
                .reward3rd(request.getReward3rd())
                .rewardDescription(request.getRewardDescription())
                .thumbnailUrl(request.getThumbnailUrl())
                .build();

        ContestData savedContest = contestDataRepository.save(contestData);
        log.info("Contest created: contestId={}", savedContest.getContestId());

        return ContestResponse.from(savedContest);
    }

    /**
     * 공모전 삭제 (관리자 전용)
     * - Cascade로 참가자 및 제출물도 함께 삭제됨
     *
     * @param contestId 공모전 ID
     */
    @Transactional
    public void deleteContest(Long contestId) {
        log.info("Deleting contest: contestId={}", contestId);

        // 공모전 존재 여부 확인
        ContestData contestData = contestDataRepository.findById(contestId)
                .orElseThrow(() -> new ContestNotFoundException(contestId));

        // 공모전 삭제 (Cascade로 ContestUser, ContestPost 등도 삭제됨)
        contestDataRepository.delete(contestData);

        log.info("Contest deleted: contestId={}", contestId);
    }
}
