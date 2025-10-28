package io.github.herbpot.miyobackend.domain.challenge.service;

import io.github.herbpot.miyobackend.domain.challenge.dto.MissionResponse;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestData;
import io.github.herbpot.miyobackend.domain.challenge.entity.Mission;
import io.github.herbpot.miyobackend.domain.challenge.exception.ContestNotFoundException;
import io.github.herbpot.miyobackend.domain.challenge.exception.MissionNotFoundException;
import io.github.herbpot.miyobackend.domain.challenge.repository.ContestDataRepository;
import io.github.herbpot.miyobackend.domain.challenge.repository.MissionRepository;
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
 * MissionService 통합 테스트
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class MissionServiceTest {

    @Autowired
    private MissionService missionService;

    @Autowired
    private ContestDataRepository contestDataRepository;

    @Autowired
    private MissionRepository missionRepository;

    private ContestData activeContest;
    private Mission mission1;
    private Mission mission2;

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

        // 미션 생성
        mission1 = Mission.builder()
                .contestId(activeContest.getContestId())
                .title("Mission 1")
                .description("Complete task 1")
                .requiredCount(5)
                .build();
        missionRepository.save(mission1);

        mission2 = Mission.builder()
                .contestId(activeContest.getContestId())
                .title("Mission 2")
                .description("Complete task 2")
                .requiredCount(10)
                .build();
        missionRepository.save(mission2);
    }

    @Test
    @DisplayName("특정 공모전의 미션 목록 조회")
    void getMissionsByContest() {
        // when
        List<MissionResponse> missions = missionService.getMissionsByContest(activeContest.getContestId());

        // then
        assertThat(missions).hasSize(2);
        assertThat(missions).extracting("title").containsExactlyInAnyOrder("Mission 1", "Mission 2");
        assertThat(missions).extracting("requiredCount").containsExactlyInAnyOrder(5, 10);
    }

    @Test
    @DisplayName("존재하지 않는 공모전의 미션 조회 시 예외 발생")
    void getMissionsByContest_NotFound() {
        // when & then
        assertThatThrownBy(() -> missionService.getMissionsByContest(999L))
                .isInstanceOf(ContestNotFoundException.class);
    }

    @Test
    @DisplayName("특정 미션 조회 성공")
    void getMissionById_Success() {
        // when
        MissionResponse response = missionService.getMissionById(
                activeContest.getContestId(), mission1.getMissionId());

        // then
        assertThat(response).isNotNull();
        assertThat(response.getTitle()).isEqualTo("Mission 1");
        assertThat(response.getDescription()).isEqualTo("Complete task 1");
        assertThat(response.getRequiredCount()).isEqualTo(5);
    }

    @Test
    @DisplayName("존재하지 않는 미션 조회 시 예외 발생")
    void getMissionById_NotFound() {
        // when & then
        assertThatThrownBy(() -> missionService.getMissionById(activeContest.getContestId(), 999L))
                .isInstanceOf(MissionNotFoundException.class)
                .hasMessageContaining("미션을 찾을 수 없습니다");
    }

    @Test
    @DisplayName("미션이 없는 공모전 조회 시 빈 목록 반환")
    void getMissionsByContest_Empty() {
        // given
        ContestData emptyContest = ContestData.builder()
                .title("Empty Contest")
                .description("No missions")
                .startDate(LocalDate.now().minusDays(1))
                .endDate(LocalDate.now().plusDays(30))
                .build();
        contestDataRepository.save(emptyContest);

        // when
        List<MissionResponse> missions = missionService.getMissionsByContest(emptyContest.getContestId());

        // then
        assertThat(missions).isEmpty();
    }
}
