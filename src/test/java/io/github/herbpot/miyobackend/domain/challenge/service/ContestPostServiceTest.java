package io.github.herbpot.miyobackend.domain.challenge.service;

import io.github.herbpot.miyobackend.domain.challenge.dto.ContestPostCreateRequest;
import io.github.herbpot.miyobackend.domain.challenge.dto.ContestPostResponse;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestData;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestPost;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestUser;
import io.github.herbpot.miyobackend.domain.challenge.exception.AlreadySubmittedException;
import io.github.herbpot.miyobackend.domain.challenge.exception.ContestNotFoundException;
import io.github.herbpot.miyobackend.domain.challenge.exception.ContestPostNotFoundException;
import io.github.herbpot.miyobackend.domain.challenge.exception.NotParticipantException;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestDataRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestPostRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * ContestPostService 통합 테스트
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class ContestPostServiceTest {

    @Autowired
    private ContestPostService contestPostService;

    @Autowired
    private ContestDataRepository contestDataRepository;

    @Autowired
    private ContestUserRepository contestUserRepository;

    @Autowired
    private ContestPostRepository contestPostRepository;

    private ContestData activeContest;
    private String participantUserId;
    private String nonParticipantUserId;

    @BeforeEach
    void setUp() {
        // 진행 중인 공모전
        activeContest = ContestData.builder()
                .title("Active Contest")
                .description("Test Description")
                .startDate(LocalDate.now().minusDays(1))
                .endDate(LocalDate.now().plusDays(30))
                .build();
        contestDataRepository.save(activeContest);

        // 참가자 등록
        participantUserId = "participantUser";
        ContestUser contestUser = ContestUser.of(activeContest.getContestId(), participantUserId);
        contestUserRepository.save(contestUser);

        // 비참가자
        nonParticipantUserId = "nonParticipantUser";
    }

    @Test
    @DisplayName("게시글 작성 성공")
    void createPost_Success() {
        // given
        ContestPostCreateRequest request = ContestPostCreateRequest.builder()
                .title("Test Post")
                .content("Test Content")
                .imageUrl("https://example.com/image.png")
                .build();

        // when
        ContestPostResponse response = contestPostService.createPost(
                activeContest.getContestId(), participantUserId, request);

        // then
        assertThat(response).isNotNull();
        assertThat(response.getTitle()).isEqualTo("Test Post");
        assertThat(response.getContent()).isEqualTo("Test Content");
        assertThat(response.getImageUrl()).isEqualTo("https://example.com/image.png");
        assertThat(response.getAuthorId()).isEqualTo(participantUserId);
    }

    @Test
    @DisplayName("존재하지 않는 공모전에 게시글 작성 시 예외 발생")
    void createPost_ContestNotFound() {
        // given
        ContestPostCreateRequest request = ContestPostCreateRequest.builder()
                .title("Test Post")
                .content("Test Content")
                .build();

        // when & then
        assertThatThrownBy(() -> contestPostService.createPost(999L, participantUserId, request))
                .isInstanceOf(ContestNotFoundException.class);
    }

    @Test
    @DisplayName("참가자가 아닌 사용자가 게시글 작성 시 예외 발생")
    void createPost_NotParticipant() {
        // given
        ContestPostCreateRequest request = ContestPostCreateRequest.builder()
                .title("Test Post")
                .content("Test Content")
                .build();

        // when & then
        assertThatThrownBy(() -> contestPostService.createPost(
                activeContest.getContestId(), nonParticipantUserId, request))
                .isInstanceOf(NotParticipantException.class)
                .hasMessageContaining("참가자가 아닙니다");
    }

    @Test
    @DisplayName("이미 제출한 사용자가 재제출 시 예외 발생")
    void createPost_AlreadySubmitted() {
        // given
        ContestPostCreateRequest request = ContestPostCreateRequest.builder()
                .title("Test Post")
                .content("Test Content")
                .build();

        // 첫 번째 제출
        contestPostService.createPost(activeContest.getContestId(), participantUserId, request);

        // when & then - 두 번째 제출
        assertThatThrownBy(() -> contestPostService.createPost(
                activeContest.getContestId(), participantUserId, request))
                .isInstanceOf(AlreadySubmittedException.class)
                .hasMessageContaining("이미 제출했습니다");
    }

    @Test
    @DisplayName("특정 공모전의 게시글 목록 조회")
    void getPostsByContest() {
        // given
        ContestPostCreateRequest request1 = ContestPostCreateRequest.builder()
                .title("Post 1")
                .content("Content 1")
                .build();
        ContestPostCreateRequest request2 = ContestPostCreateRequest.builder()
                .title("Post 2")
                .content("Content 2")
                .build();

        contestPostService.createPost(activeContest.getContestId(), participantUserId, request1);

        // 다른 참가자 추가
        String anotherUser = "anotherUser";
        ContestUser anotherContestUser = ContestUser.of(activeContest.getContestId(), anotherUser);
        contestUserRepository.save(anotherContestUser);
        contestPostService.createPost(activeContest.getContestId(), anotherUser, request2);

        // when
        List<ContestPostResponse> posts = contestPostService.getPostsByContest(
                activeContest.getContestId(), null);

        // then
        assertThat(posts).hasSize(2);
        assertThat(posts).extracting("title").containsExactlyInAnyOrder("Post 1", "Post 2");
    }

    @Test
    @DisplayName("특정 게시글 조회 성공")
    void getPostById_Success() {
        // given
        ContestPostCreateRequest request = ContestPostCreateRequest.builder()
                .title("Test Post")
                .content("Test Content")
                .build();
        ContestPostResponse created = contestPostService.createPost(
                activeContest.getContestId(), participantUserId, request);

        // when
        ContestPostResponse response = contestPostService.getPostById(created.getPostId(), null);

        // then
        assertThat(response).isNotNull();
        assertThat(response.getTitle()).isEqualTo("Test Post");
        assertThat(response.getAuthorId()).isEqualTo(participantUserId);
    }

    @Test
    @DisplayName("존재하지 않는 게시글 조회 시 예외 발생")
    void getPostById_NotFound() {
        // when & then
        assertThatThrownBy(() -> contestPostService.getPostById(999L, null))
                .isInstanceOf(ContestPostNotFoundException.class)
                .hasMessageContaining("게시글을 찾을 수 없습니다");
    }

    @Test
    @DisplayName("공감 추가 성공")
    void addEmpathy_Success() {
        // given
        ContestPostCreateRequest request = ContestPostCreateRequest.builder()
                .title("Test Post")
                .content("Test Content")
                .build();
        ContestPostResponse created = contestPostService.createPost(
                activeContest.getContestId(), participantUserId, request);

        String empathyUserId = "empathyUser";

        // when
        contestPostService.addEmpathy(created.getPostId(), empathyUserId);

        // then
        ContestPost post = contestPostRepository.findById(created.getPostId()).orElseThrow();
        assertThat(post.getEmpathyCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("공감 취소 성공")
    void removeEmpathy_Success() {
        // given
        ContestPostCreateRequest request = ContestPostCreateRequest.builder()
                .title("Test Post")
                .content("Test Content")
                .build();
        ContestPostResponse created = contestPostService.createPost(
                activeContest.getContestId(), participantUserId, request);

        String empathyUserId = "empathyUser";
        contestPostService.addEmpathy(created.getPostId(), empathyUserId);

        // when
        contestPostService.removeEmpathy(created.getPostId(), empathyUserId);

        // then
        ContestPost post = contestPostRepository.findById(created.getPostId()).orElseThrow();
        assertThat(post.getEmpathyCount()).isEqualTo(0);
    }

    @Test
    @DisplayName("사용자의 게시글 목록 조회")
    void getPostsByUser() {
        // given
        ContestPostCreateRequest request = ContestPostCreateRequest.builder()
                .title("User Post")
                .content("User Content")
                .build();
        contestPostService.createPost(activeContest.getContestId(), participantUserId, request);

        // when
        List<ContestPostResponse> posts = contestPostService.getPostsByUser(participantUserId, null);

        // then
        assertThat(posts).hasSize(1);
        assertThat(posts.get(0).getTitle()).isEqualTo("User Post");
        assertThat(posts.get(0).getAuthorId()).isEqualTo(participantUserId);
    }
}
