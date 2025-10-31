package io.github.herbpot.miyobackend.domain.challenge.repository;

import io.github.herbpot.miyobackend.domain.challenge.entity.ContestPost;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * ContestPostRepository
 * - ContestPost 테이블에 대한 JPA Repository
 * - 공모전 제출물 관리
 */
@Repository
public interface ContestPostRepository extends JpaRepository<ContestPost, Long> {

    /**
     * 특정 공모전의 제출물 목록 조회 (페이징)
     *
     * @param contestId 공모전 ID
     * @param pageable 페이징 정보
     * @return 제출물 목록
     */
    @Query("SELECT cp FROM ContestPost cp WHERE cp.contestId = :contestId AND cp.parentPostId IS NULL ORDER BY cp.createdAt DESC")
    Page<ContestPost> findByContestId(@Param("contestId") Long contestId, Pageable pageable);

    /**
     * 특정 공모전의 제출물 목록 조회 (정렬 지원)
     * - Pageable의 Sort를 사용하여 동적 정렬 지원
     *
     * @param contestId 공모전 ID
     * @param pageable 페이징 및 정렬 정보
     * @return 제출물 목록
     */
    @Query("SELECT cp FROM ContestPost cp WHERE cp.contestId = :contestId AND cp.parentPostId IS NULL")
    Page<ContestPost> findByContestIdWithSort(@Param("contestId") Long contestId, Pageable pageable);

    /**
     * 특정 제출물의 댓글 목록 조회
     *
     * @param parentPostId 부모 제출물 ID
     * @param pageable 페이징 정보
     * @return 댓글 목록
     */
    @Query("SELECT cp FROM ContestPost cp WHERE cp.parentPostId = :parentPostId ORDER BY cp.createdAt ASC")
    Page<ContestPost> findCommentsByParentPostId(@Param("parentPostId") Long parentPostId, Pageable pageable);

    /**
     * 특정 제출물의 댓글 목록 조회 (페이징 없이 전체 조회)
     *
     * @param parentPostId 부모 제출물 ID
     * @return 댓글 목록
     */
    @Query("SELECT cp FROM ContestPost cp WHERE cp.parentPostId = :parentPostId ORDER BY cp.createdAt ASC")
    List<ContestPost> findCommentsByParentPostIdWithoutPaging(@Param("parentPostId") Long parentPostId);

    /**
     * 여러 댓글의 대댓글을 한 번에 조회 (N+1 문제 방지)
     *
     * @param parentPostIds 부모 댓글 ID 목록
     * @return 대댓글 목록
     */
    @Query("SELECT cp FROM ContestPost cp WHERE cp.parentPostId IN :parentPostIds ORDER BY cp.parentPostId ASC, cp.createdAt ASC")
    List<ContestPost> findRepliesByParentPostIds(@Param("parentPostIds") List<Long> parentPostIds);

    /**
     * 특정 공모전에서 사용자의 제출물 조회 (1인 1제출 확인용)
     *
     * @param contestId 공모전 ID
     * @param userId 사용자 ID
     * @return 제출물
     */
    @Query("SELECT cp FROM ContestPost cp WHERE cp.contestId = :contestId AND cp.userId = :userId AND cp.parentPostId IS NULL")
    Optional<ContestPost> findByContestIdAndUserId(@Param("contestId") Long contestId, @Param("userId") String userId);

    /**
     * 특정 공모전의 제출물 수 조회
     *
     * @param contestId 공모전 ID
     * @return 제출물 수
     */
    @Query("SELECT COUNT(cp) FROM ContestPost cp WHERE cp.contestId = :contestId AND cp.parentPostId IS NULL")
    Long countByContestId(@Param("contestId") Long contestId);

    /**
     * 특정 공모전의 상위 N개 제출물 조회 (공감 순)
     *
     * @param contestId 공모전 ID
     * @param pageable 페이징 정보 (size로 개수 제한)
     * @return 상위 제출물 목록
     */
    @Query("SELECT cp FROM ContestPost cp WHERE cp.contestId = :contestId AND cp.parentPostId IS NULL ORDER BY cp.empathy DESC, cp.createdAt DESC")
    List<ContestPost> findTopByContestIdOrderByEmpathy(@Param("contestId") Long contestId, Pageable pageable);

    /**
     * 제출물 ID와 작성자 ID로 조회 (삭제/수정 권한 확인용)
     *
     * @param id 제출물 ID
     * @param userId 작성자 ID
     * @return 제출물
     */
    @Query("SELECT cp FROM ContestPost cp WHERE cp.id = :id AND cp.userId = :userId")
    Optional<ContestPost> findByIdAndUserId(@Param("id") Long id, @Param("userId") String userId);
}
