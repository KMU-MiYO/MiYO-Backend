package io.github.herbpot.miyobackend.domain.community.repository.read;

import io.github.herbpot.miyobackend.domain.community.entity.read.EmpathyReadModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * EmpathyReadRepository (Read DB)
 * - empathy_data 테이블에 대한 JPA Repository
 * - Read DB 사용
 * - 공감 조회 전용
 */
@Repository
public interface EmpathyReadRepository extends JpaRepository<EmpathyReadModel, Long> {

    /**
     * 특정 게시글의 공감 수 조회
     *
     * @param postId 게시글 ID
     * @return 공감 수
     */
    @Query("SELECT COUNT(e) FROM EmpathyReadModel e WHERE e.postId = :postId")
    Long countByPostId(@Param("postId") Long postId);

    /**
     * 사용자가 특정 게시글에 공감했는지 확인
     *
     * @param userId 사용자 ID
     * @param postId 게시글 ID
     * @return 공감 여부
     */
    boolean existsByUserIdAndPostId(String userId, Long postId);

    /**
     * 사용자의 특정 게시글 공감 조회
     *
     * @param userId 사용자 ID
     * @param postId 게시글 ID
     * @return 공감 데이터
     */
    Optional<EmpathyReadModel> findByUserIdAndPostId(String userId, Long postId);

    /**
     * 여러 게시글의 공감 수를 한번에 조회
     *
     * @param postIds 게시글 ID 리스트
     * @return 게시글별 공감 수 (postId, count)
     */
    @Query("SELECT e.postId, COUNT(e) FROM EmpathyReadModel e WHERE e.postId IN :postIds GROUP BY e.postId")
    List<Object[]> countByPostIds(@Param("postIds") List<Long> postIds);

    /**
     * 사용자가 공감한 게시글 ID 목록 조회
     *
     * @param userId 사용자 ID
     * @return 공감한 게시글 ID 리스트
     */
    @Query("SELECT e.postId FROM EmpathyReadModel e WHERE e.userId = :userId")
    List<Long> findPostIdsByUserId(@Param("userId") String userId);
}
