package io.github.herbpot.miyobackend.domain.challenge.repository;

import io.github.herbpot.miyobackend.domain.challenge.entity.UserMissionProgress;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * UserMissionProgressRepository
 * - UserMissionProgress 테이블에 대한 JPA Repository
 * - 유저별 미션 진행 현황 관리
 */
@Repository
public interface UserMissionProgressRepository extends JpaRepository<UserMissionProgress, Long> {

    /**
     * 특정 사용자의 특정 미션 진행 현황 조회
     *
     * @param missionId 미션 ID
     * @param userId 사용자 ID
     * @return 진행 현황
     */
    @Query("SELECT ump FROM UserMissionProgress ump WHERE ump.missionId = :missionId AND ump.userId = :userId")
    Optional<UserMissionProgress> findByMissionIdAndUserId(@Param("missionId") Long missionId, @Param("userId") String userId);

    /**
     * 특정 사용자의 모든 미션 진행 현황 조회
     *
     * @param userId 사용자 ID
     * @return 진행 현황 목록
     */
    @Query("SELECT ump FROM UserMissionProgress ump WHERE ump.userId = :userId ORDER BY ump.updatedAt DESC")
    List<UserMissionProgress> findByUserId(@Param("userId") String userId);

    /**
     * 특정 사용자의 완료된 미션 목록 조회
     *
     * @param userId 사용자 ID
     * @return 완료된 미션 목록
     */
    @Query("SELECT ump FROM UserMissionProgress ump WHERE ump.userId = :userId AND ump.completed = true ORDER BY ump.completedAt DESC")
    List<UserMissionProgress> findCompletedMissionsByUserId(@Param("userId") String userId);

    /**
     * 특정 사용자의 진행 중인 미션 목록 조회
     *
     * @param userId 사용자 ID
     * @return 진행 중인 미션 목록
     */
    @Query("SELECT ump FROM UserMissionProgress ump WHERE ump.userId = :userId AND ump.completed = false ORDER BY ump.updatedAt DESC")
    List<UserMissionProgress> findInProgressMissionsByUserId(@Param("userId") String userId);

    /**
     * 특정 미션의 완료자 수 조회
     *
     * @param missionId 미션 ID
     * @return 완료자 수
     */
    @Query("SELECT COUNT(ump) FROM UserMissionProgress ump WHERE ump.missionId = :missionId AND ump.completed = true")
    Long countCompletedByMissionId(@Param("missionId") Long missionId);

    /**
     * 특정 미션의 모든 진행 현황 리셋 (주간/월간 미션 갱신 시)
     *
     * @param missionId 미션 ID
     */
    @Modifying
    @Query("UPDATE UserMissionProgress ump SET ump.currentCount = 0, ump.completed = false, ump.completedAt = null WHERE ump.missionId = :missionId")
    void resetProgressByMissionId(@Param("missionId") Long missionId);

    /**
     * 여러 미션의 진행 현황 리셋 (배치 처리용)
     *
     * @param missionIds 미션 ID 목록
     */
    @Modifying
    @Query("UPDATE UserMissionProgress ump SET ump.currentCount = 0, ump.completed = false, ump.completedAt = null WHERE ump.missionId IN :missionIds")
    void resetProgressByMissionIds(@Param("missionIds") List<Long> missionIds);

    /**
     * 특정 미션의 모든 진행 현황 삭제 (미션 삭제 시)
     *
     * @param missionId 미션 ID
     */
    @Modifying
    @Query("DELETE FROM UserMissionProgress ump WHERE ump.missionId = :missionId")
    void deleteByMissionId(@Param("missionId") Long missionId);
}
