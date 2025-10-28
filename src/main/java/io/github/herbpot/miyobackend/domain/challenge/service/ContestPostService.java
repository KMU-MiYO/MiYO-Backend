package io.github.herbpot.miyobackend.domain.challenge.service;

import io.github.herbpot.miyobackend.client.UserServiceClient;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestPostCommentRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestPostCreateRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestPostResponse;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestPost;
import io.github.herbpot.miyobackend.domain.challenge.exception.AlreadySubmittedException;
import io.github.herbpot.miyobackend.domain.challenge.exception.ContestNotFoundException;
import io.github.herbpot.miyobackend.domain.challenge.exception.ContestPostNotFoundException;
import io.github.herbpot.miyobackend.domain.challenge.exception.NotParticipantException;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestDataRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestPostRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestUserRepository;
import io.github.herbpot.miyobackend.domain.challenge.validator.MissionValidatorFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * ContestPostService
 * - 공모전 제출물 작성, 조회, 삭제 등의 작업 담당
 * - 제출물 작성 시 미션 진행도 업데이트 (Strategy Pattern 사용)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ContestPostService {

    private final ContestPostRepository contestPostRepository;
    private final ContestDataRepository contestDataRepository;
    private final ContestUserRepository contestUserRepository;
    private final UserServiceClient userServiceClient;
    private final MissionValidatorFactory missionValidatorFactory;

    /**
     * 공모전 제출물 작성
     * - 1인 1제출 제약 확인
     * - 제출물 저장
     * - 미션 진행도 업데이트 (proposal 미션)
     *
     * @param contestId 공모전 ID
     * @param request 제출물 작성 요청
     * @param userId 작성자 ID
     * @return 생성된 제출물 정보
     */
    @Transactional
    public ContestPostResponse createPost(Long contestId, ContestPostCreateRequest request, String userId) {
        log.info("Creating contest post: contestId={}, userId={}", contestId, userId);

        // 공모전 존재 여부 확인
        if (!contestDataRepository.existsById(contestId)) {
            log.warn("Contest not found: contestId={}", contestId);
            throw new ContestNotFoundException(contestId);
        }

        // 사용자가 공모전에 참가했는지 확인
        if (!contestUserRepository.existsByContestIdAndUserId(contestId, userId)) {
            log.warn("User not participated in contest: contestId={}, userId={}", contestId, userId);
            throw new NotParticipantException(contestId, userId);
        }

        // 1인 1제출 제약 확인
        if (contestPostRepository.findByContestIdAndUserId(contestId, userId).isPresent()) {
            log.warn("User already submitted: contestId={}, userId={}", contestId, userId);
            throw new AlreadySubmittedException(contestId, userId);
        }

        // 사용자 닉네임 조회
        String userNickname = userServiceClient.getUserNickname(userId);

        // 제출물 생성
        ContestPost contestPost = ContestPost.builder()
                .contestId(contestId)
                .parentPostId(null)
                .userId(userId)
                .title(request.getTitle())
                .content(request.getContent())
                .category(request.getCategory())
                .imagePath(request.getImagePath())
                .fileUrl(request.getFileUrl())
                .build();

        ContestPost savedPost = contestPostRepository.save(contestPost);
        log.info("Contest post saved: postId={}, contestId={}", savedPost.getId(), contestId);

        // 미션 진행도 업데이트 (proposal 미션)
        try {
            var validator = missionValidatorFactory.getValidator("proposal");
            if (validator != null) {
                validator.validateAndUpdateProgress(userId, savedPost.getId());
                log.info("Proposal mission updated: userId={}, postId={}", userId, savedPost.getId());
            }
        } catch (Exception e) {
            log.error("Failed to update mission progress", e);
            // 미션 업데이트 실패해도 제출물 작성은 성공으로 처리
        }

        return ContestPostResponse.fromWithNickname(savedPost, userNickname);
    }

    /**
     * 공모전 제출물 목록 조회
     *
     * @param contestId 공모전 ID
     * @param pageable 페이징 정보
     * @return 제출물 목록
     */
    @Transactional(readOnly = true)
    public Page<ContestPostResponse> getPostsByContestId(Long contestId, Pageable pageable) {
        log.info("Getting contest posts: contestId={}, page={}", contestId, pageable.getPageNumber());

        Page<ContestPost> posts = contestPostRepository.findByContestId(contestId, pageable);

        return posts.map(post -> {
            String userNickname = userServiceClient.getUserNickname(post.getUserId());
            return ContestPostResponse.fromWithNickname(post, userNickname);
        });
    }

    /**
     * 공모전 제출물 상세 조회
     *
     * @param postId 제출물 ID
     * @return 제출물 상세 정보
     */
    @Transactional(readOnly = true)
    public ContestPostResponse getPostById(Long postId) {
        log.info("Getting contest post: postId={}", postId);

        ContestPost post = contestPostRepository.findById(postId)
                .orElseThrow(() -> new ContestPostNotFoundException(postId));

        String userNickname = userServiceClient.getUserNickname(post.getUserId());
        return ContestPostResponse.fromWithNickname(post, userNickname);
    }

    /**
     * 제출물 댓글 작성
     *
     * @param parentPostId 부모 제출물 ID
     * @param request 댓글 작성 요청
     * @param userId 작성자 ID
     * @return 생성된 댓글 정보
     */
    @Transactional
    public ContestPostResponse createComment(Long parentPostId, ContestPostCommentRequest request, String userId) {
        log.info("Creating comment on contest post: parentPostId={}, userId={}", parentPostId, userId);

        // 부모 제출물 존재 여부 확인
        ContestPost parentPost = contestPostRepository.findById(parentPostId)
                .orElseThrow(() -> new ContestPostNotFoundException(parentPostId));

        // 사용자 닉네임 조회
        String userNickname = userServiceClient.getUserNickname(userId);

        // 댓글 생성 (부모의 contestId, title, category 상속)
        ContestPost comment = ContestPost.builder()
                .contestId(parentPost.getContestId())
                .parentPostId(parentPostId)
                .userId(userId)
                .title(parentPost.getTitle())  // 부모의 제목 상속
                .content(request.getContent())
                .category(parentPost.getCategory())  // 부모의 카테고리 상속
                .imagePath(null)  // 댓글은 이미지 없음
                .fileUrl(null)  // 댓글은 파일 없음
                .build();

        ContestPost savedComment = contestPostRepository.save(comment);
        log.info("Comment saved: commentId={}, parentPostId={}", savedComment.getId(), parentPostId);

        // 미션 진행도 업데이트 (comment 미션)
        try {
            var validator = missionValidatorFactory.getValidator("comment");
            if (validator != null) {
                validator.validateAndUpdateProgress(userId, savedComment.getId());
                log.info("Comment mission updated: userId={}, commentId={}", userId, savedComment.getId());
            }
        } catch (Exception e) {
            log.error("Failed to update mission progress", e);
        }

        return ContestPostResponse.fromWithNickname(savedComment, userNickname);
    }

    /**
     * 제출물 댓글 목록 조회
     *
     * @param parentPostId 부모 제출물 ID
     * @param pageable 페이징 정보
     * @return 댓글 목록
     */
    @Transactional(readOnly = true)
    public Page<ContestPostResponse> getCommentsByPostId(Long parentPostId, Pageable pageable) {
        log.info("Getting comments: parentPostId={}, page={}", parentPostId, pageable.getPageNumber());

        Page<ContestPost> comments = contestPostRepository.findCommentsByParentPostId(parentPostId, pageable);

        return comments.map(comment -> {
            String userNickname = userServiceClient.getUserNickname(comment.getUserId());
            return ContestPostResponse.fromWithNickname(comment, userNickname);
        });
    }

    /**
     * 공감 추가
     *
     * @param postId 제출물 ID
     * @param userId 사용자 ID
     */
    @Transactional
    public void addEmpathy(Long postId, String userId) {
        log.info("Adding empathy: postId={}, userId={}", postId, userId);

        ContestPost post = contestPostRepository.findById(postId)
                .orElseThrow(() -> new ContestPostNotFoundException(postId));

        post.incrementEmpathy();
        contestPostRepository.save(post);

        // 미션 진행도 업데이트 (empathy 미션)
        try {
            var validator = missionValidatorFactory.getValidator("empathy");
            if (validator != null) {
                validator.validateAndUpdateProgress(userId, postId);
                log.info("Empathy mission updated: userId={}, postId={}", userId, postId);
            }
        } catch (Exception e) {
            log.error("Failed to update mission progress", e);
        }

        log.info("Empathy added: postId={}, currentEmpathy={}", postId, post.getEmpathy());
    }

    /**
     * 공감 취소
     *
     * @param postId 제출물 ID
     * @param userId 사용자 ID
     */
    @Transactional
    public void removeEmpathy(Long postId, String userId) {
        log.info("Removing empathy: postId={}, userId={}", postId, userId);

        ContestPost post = contestPostRepository.findById(postId)
                .orElseThrow(() -> new ContestPostNotFoundException(postId));

        post.decrementEmpathy();
        contestPostRepository.save(post);

        log.info("Empathy removed: postId={}, currentEmpathy={}", postId, post.getEmpathy());
    }
}
