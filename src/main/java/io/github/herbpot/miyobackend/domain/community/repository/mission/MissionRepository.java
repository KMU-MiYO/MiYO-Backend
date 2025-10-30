package io.github.herbpot.miyobackend.domain.community.repository.mission;

import io.github.herbpot.miyobackend.domain.community.entity.mission.Mission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

/**
 * MissionRepository
 * - Mission 테이블에 대한 JPA Repository
 */
@Repository
public interface MissionRepository extends JpaRepository<Mission, Long> {

    /**
     * 현재 활성화된 미션 조회 (startDate <= currentDate <= endDate)
     */
    @Query("SELECT m FROM Mission m WHERE m.startDate <= :currentDate AND m.endDate >= :currentDate")
    List<Mission> findActiveMissions(@Param("currentDate") LocalDate currentDate);

    /**
     * 특정 카테고리의 활성화된 미션 조회
     */
    @Query("SELECT m FROM Mission m WHERE m.category = :category AND m.startDate <= :currentDate AND m.endDate >= :currentDate")
    List<Mission> findActiveMissionsByCategory(@Param("category") String category, @Param("currentDate") LocalDate currentDate);
}
