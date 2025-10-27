package io.github.herbpot.miyobackend.domain.challenge.repository;

import io.github.herbpot.miyobackend.domain.challenge.entity.Mission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

/**
 * MissionRepository
 * - Mission 테이블에 대한 JPA Repository
 * - 미션 정의 조회 및 관리
 */
@Repository
public interface MissionRepository extends JpaRepository<Mission, Long> {

    /**
     * 현재 활성화된 미션 조회
     * - 시작일 <= 현재 날짜 <= 종료일
     *
     * @param currentDate 현재 날짜
     * @return 활성 미션 목록
     */
    @Query("SELECT m FROM Mission m WHERE m.startDate <= :currentDate AND m.endDate >= :currentDate ORDER BY m.periodType, m.createdAt DESC")
    List<Mission> findActiveMissions(@Param("currentDate") LocalDate currentDate);

    /**
     * 특정 기간 타입의 활성 미션 조회
     *
     * @param periodType 기간 타입 (weekly, monthly)
     * @param currentDate 현재 날짜
     * @return 활성 미션 목록
     */
    @Query("SELECT m FROM Mission m WHERE m.periodType = :periodType AND m.startDate <= :currentDate AND m.endDate >= :currentDate ORDER BY m.createdAt DESC")
    List<Mission> findActiveMissionsByPeriodType(@Param("periodType") Mission.PeriodType periodType, @Param("currentDate") LocalDate currentDate);

    /**
     * 특정 카테고리의 활성 미션 조회
     *
     * @param category 미션 카테고리
     * @param currentDate 현재 날짜
     * @return 활성 미션 목록
     */
    @Query("SELECT m FROM Mission m WHERE m.category = :category AND m.startDate <= :currentDate AND m.endDate >= :currentDate")
    List<Mission> findActiveMissionsByCategory(@Param("category") String category, @Param("currentDate") LocalDate currentDate);
}
