package io.github.herbpot.miyobackend.domain.challenge.repository;

import io.github.herbpot.miyobackend.domain.challenge.entity.ContestUser;
import io.github.herbpot.miyobackend.domain.challenge.entity.ContestUserId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * ContestUserRepository
 * - ContestUser 테이블에 대한 JPA Repository
 * - 공모전 참가자 정보 관리
 */
@Repository
public interface ContestUserRepository extends JpaRepository<ContestUser, ContestUserId> {

    /**
     * 특정 공모전의 참가자 수 조회
     *
     * @param contestId 공모전 ID
     * @return 참가자 수
     */
    @Query("SELECT COUNT(cu) FROM ContestUser cu WHERE cu.id.contestId = :contestId")
    Long countByContestId(@Param("contestId") Long contestId);

    /**
     * 특정 공모전의 참가자 목록 조회
     *
     * @param contestId 공모전 ID
     * @return 참가자 목록
     */
    @Query("SELECT cu FROM ContestUser cu WHERE cu.id.contestId = :contestId ORDER BY cu.joinedAt DESC")
    List<ContestUser> findByContestId(@Param("contestId") Long contestId);

    /**
     * 특정 사용자가 참가한 공모전 목록 조회
     *
     * @param userId 사용자 ID
     * @return 참가한 공모전 목록
     */
    @Query("SELECT cu FROM ContestUser cu WHERE cu.id.userId = :userId ORDER BY cu.joinedAt DESC")
    List<ContestUser> findByUserId(@Param("userId") String userId);

    /**
     * 사용자가 특정 공모전에 참가했는지 확인
     *
     * @param contestId 공모전 ID
     * @param userId 사용자 ID
     * @return 참가 여부
     */
    @Query("SELECT COUNT(cu) > 0 FROM ContestUser cu WHERE cu.id.contestId = :contestId AND cu.id.userId = :userId")
    boolean existsByContestIdAndUserId(@Param("contestId") Long contestId, @Param("userId") String userId);
}
