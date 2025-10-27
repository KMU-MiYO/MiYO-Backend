package io.github.herbpot.miyobackend.domain.challenge.repository;

import io.github.herbpot.miyobackend.domain.challenge.entity.ContestData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

/**
 * ContestDataRepository
 * - ContestData 테이블에 대한 JPA Repository
 * - 공모전 메타데이터 조회 및 관리
 */
@Repository
public interface ContestDataRepository extends JpaRepository<ContestData, Long> {

    /**
     * 현재 진행 중인 공모전 조회
     * - 시작일 <= 현재 날짜 <= 종료일
     *
     * @param currentDate 현재 날짜
     * @return 진행 중인 공모전 목록
     */
    @Query("SELECT c FROM ContestData c WHERE c.startDate <= :currentDate AND c.endDate >= :currentDate ORDER BY c.createdAt DESC")
    List<ContestData> findActiveContests(@Param("currentDate") LocalDate currentDate);

    /**
     * 종료된 공모전 조회
     * - 종료일 < 현재 날짜
     *
     * @param currentDate 현재 날짜
     * @return 종료된 공모전 목록
     */
    @Query("SELECT c FROM ContestData c WHERE c.endDate < :currentDate ORDER BY c.endDate DESC")
    List<ContestData> findEndedContests(@Param("currentDate") LocalDate currentDate);

    /**
     * 예정된 공모전 조회
     * - 시작일 > 현재 날짜
     *
     * @param currentDate 현재 날짜
     * @return 예정된 공모전 목록
     */
    @Query("SELECT c FROM ContestData c WHERE c.startDate > :currentDate ORDER BY c.startDate ASC")
    List<ContestData> findUpcomingContests(@Param("currentDate") LocalDate currentDate);
}
