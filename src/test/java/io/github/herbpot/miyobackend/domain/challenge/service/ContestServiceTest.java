package io.github.herbpot.miyobackend.domain.challenge.service;

import io.github.herbpot.miyobackend.domain.challenge.dto.ContestResponse;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestData;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestUser;
import io.github.herbpot.miyobackend.domain.challenge.exception.AlreadyJoinedException;
import io.github.herbpot.miyobackend.domain.challenge.exception.ContestNotFoundException;
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
 * ContestService 통합 테스트
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class ContestServiceTest {

    @Autowired
    private ContestService contestService;

    @Autowired
    private ContestDataRepository contestDataRepository;

    @Autowired
    private ContestUserRepository contestUserRepository;

    @Autowired
    private ContestPostRepository contestPostRepository;

    private ContestData activeContest;
    private ContestData expiredContest;

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

        // 종료된 공모전
        expiredContest = ContestData.builder()
                .title("Expired Contest")
                .description("Expired Description")
                .startDate(LocalDate.now().minusDays(60))
                .endDate(LocalDate.now().minusDays(30))
                .build();
        contestDataRepository.save(expiredContest);
    }

    @Test
    @DisplayName("진행 중인 공모전 목록 조회")
    void getActiveContests() {
        // when
        List<ContestResponse> contests = contestService.getActiveContests();

        // then
        assertThat(contests).isNotEmpty();
        assertThat(contests).anyMatch(c -> c.getTitle().equals("Active Contest"));
        assertThat(contests).noneMatch(c -> c.getTitle().equals("Expired Contest"));
    }

    @Test
    @DisplayName("특정 공모전 조회 성공")
    void getContestById_Success() {
        // when
        ContestResponse response = contestService.getContestById(activeContest.getContestId(), null);

        // then
        assertThat(response).isNotNull();
        assertThat(response.getTitle()).isEqualTo("Active Contest");
        assertThat(response.getDescription()).isEqualTo("Test Description");
    }

    @Test
    @DisplayName("존재하지 않는 공모전 조회 시 예외 발생")
    void getContestById_NotFound() {
        // when & then
        assertThatThrownBy(() -> contestService.getContestById(999L, null))
                .isInstanceOf(ContestNotFoundException.class)
                .hasMessageContaining("공모전을 찾을 수 없습니다");
    }

    @Test
    @DisplayName("공모전 참가 성공")
    void joinContest_Success() {
        // given
        String userId = "testUser";

        // when
        contestService.joinContest(activeContest.getContestId(), userId);

        // then
        boolean isParticipant = contestUserRepository.existsByContestIdAndUserId(
                activeContest.getContestId(), userId);
        assertThat(isParticipant).isTrue();
    }

    @Test
    @DisplayName("존재하지 않는 공모전 참가 시 예외 발생")
    void joinContest_ContestNotFound() {
        // when & then
        assertThatThrownBy(() -> contestService.joinContest(999L, "testUser"))
                .isInstanceOf(ContestNotFoundException.class);
    }

    @Test
    @DisplayName("이미 참가한 공모전 재참가 시 예외 발생")
    void joinContest_AlreadyJoined() {
        // given
        String userId = "testUser";
        ContestUser contestUser = ContestUser.of(activeContest.getContestId(), userId);
        contestUserRepository.save(contestUser);

        // when & then
        assertThatThrownBy(() -> contestService.joinContest(activeContest.getContestId(), userId))
                .isInstanceOf(AlreadyJoinedException.class)
                .hasMessageContaining("이미 참가한 공모전입니다");
    }

    @Test
    @DisplayName("사용자가 참가한 공모전 목록 조회")
    void getMyContests() {
        // given
        String userId = "testUser";
        ContestUser contestUser = ContestUser.of(activeContest.getContestId(), userId);
        contestUserRepository.save(contestUser);

        // when
        List<ContestResponse> myContests = contestService.getMyContests(userId);

        // then
        assertThat(myContests).hasSize(1);
        assertThat(myContests.get(0).getTitle()).isEqualTo("Active Contest");
    }
}
