package io.github.herbpot.miyobackend.domain.challenge.repository;

import io.github.herbpot.miyobackend.domain.challenge.entity.ContestEmpathy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * ContestEmpathyRepository
 * - ContestEmpathy 테이블에 대한 JPA Repository
 * - 공감 정보 관리
 */
@Repository
public interface ContestEmpathyRepository extends JpaRepository<ContestEmpathy, Long> {

    /**
     * 특정 사용자가 특정 게시물에 공감했는지 확인
     *
     * @param userId 사용자 ID
     * @param postId 게시물 ID
     * @return 공감 정보
     */
    Optional<ContestEmpathy> findByUserIdAndPostId(String userId, Long postId);

    /**
     * 특정 사용자가 특정 게시물에 공감했는지 여부 확인
     *
     * @param userId 사용자 ID
     * @param postId 게시물 ID
     * @return 공감 여부
     */
    boolean existsByUserIdAndPostId(String userId, Long postId);

    /**
     * 특정 게시물의 공감 개수 조회
     *
     * @param postId 게시물 ID
     * @return 공감 개수
     */
    @Query("SELECT COUNT(e) FROM ContestEmpathy e WHERE e.postId = :postId")
    Long countByPostId(@Param("postId") Long postId);

    /**
     * 여러 게시물의 공감 개수를 일괄 조회
     *
     * @param postIds 게시물 ID 목록
     * @return 게시물별 공감 개수 (postId, count)
     */
    @Query("SELECT e.postId, COUNT(e) FROM ContestEmpathy e WHERE e.postId IN :postIds GROUP BY e.postId")
    List<Object[]> countByPostIds(@Param("postIds") List<Long> postIds);

    /**
     * 특정 게시물에 공감한 사용자 목록 조회
     *
     * @param postId 게시물 ID
     * @return 사용자 ID 목록
     */
    @Query("SELECT e.userId FROM ContestEmpathy e WHERE e.postId = :postId")
    List<String> findUserIdsByPostId(@Param("postId") Long postId);

    /**
     * 특정 사용자와 게시물 ID로 공감 정보 삭제
     *
     * @param userId 사용자 ID
     * @param postId 게시물 ID
     */
    void deleteByUserIdAndPostId(String userId, Long postId);

    /**
     * 특정 게시물의 모든 공감 삭제
     *
     * @param postId 게시물 ID
     */
    void deleteByPostId(Long postId);
}
