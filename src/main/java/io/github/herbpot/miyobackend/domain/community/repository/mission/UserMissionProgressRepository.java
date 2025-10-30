package io.github.herbpot.miyobackend.domain.community.repository.mission;

import io.github.herbpot.miyobackend.domain.community.entity.mission.UserMissionProgress;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * UserMissionProgressRepository
 * - UserMissionProgress 테이블에 대한 JPA Repository
 */
@Repository
public interface UserMissionProgressRepository extends JpaRepository<UserMissionProgress, Long> {

    /**
     * 특정 사용자의 특정 미션 진행 현황 조회
     */
    @Query("SELECT ump FROM UserMissionProgress ump WHERE ump.missionId = :missionId AND ump.userId = :userId")
    Optional<UserMissionProgress> findByMissionIdAndUserId(@Param("missionId") Long missionId, @Param("userId") String userId);

    /**
     * 특정 사용자의 모든 미션 진행 현황 조회
     */
    @Query("SELECT ump FROM UserMissionProgress ump WHERE ump.userId = :userId ORDER BY ump.updatedAt DESC")
    List<UserMissionProgress> findByUserId(@Param("userId") String userId);
}
