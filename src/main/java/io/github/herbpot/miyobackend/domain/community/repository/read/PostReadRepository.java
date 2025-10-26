package io.github.herbpot.miyobackend.domain.community.repository.read;

import io.github.herbpot.miyobackend.domain.community.entity.PostReadModel;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * PostReadRepository (Read Model Repository)
 * - posts_read 테이블에 대한 JPA Repository
 * - Read DB 사용
 * - 게시글 조회 전용 (CQRS Read Model)
 * - MySQL Spatial Function을 활용한 위치 기반 검색
 */
@Repository
public interface PostReadRepository extends JpaRepository<PostReadModel, Long> {

    /**
     * 좌표 기반 반경 내 게시글 검색
     * - ST_Distance_Sphere: 두 Point 간의 구면 거리 계산 (미터 단위)
     * - POINT(위도, 경도) 순서 (SRID 4326)
     * - parentPostId가 null인 게시글만 조회 (댓글 제외)
     * - 공감수는 서비스 레이어에서 조회하여 정렬
     *
     * @param point WKT 형식의 POINT (SRID 4326)
     * @param radiusMeters 검색 반경 (미터)
     * @param pageable 페이징 정보
     * @return 반경 내 게시글 목록 (댓글 제외)
     */
    @Query(value = "SELECT p FROM PostReadModel p " +
            "WHERE ST_Distance_Sphere(p.location, ST_GeomFromText(:point, 4326)) <= :radiusMeters " +
            "AND p.parentPostId IS NULL " +
            "ORDER BY p.createdAt DESC")
    Page<PostReadModel> findByLocationWithinRadius(
            @Param("point") String point,
            @Param("radiusMeters") double radiusMeters,
            Pageable pageable
    );

    /**
     * 게시글 ID로 상세 조회
     *
     * @param postId 게시글 ID
     * @return 게시글 상세 정보
     */
    Optional<PostReadModel> findByPostId(Long postId);

    /**
     * 부모 게시글 ID로 댓글 목록 조회
     * - parentPostId가 일치하는 댓글들만 조회
     * - 최신순으로 정렬
     *
     * @param parentPostId 부모 게시글 ID
     * @param pageable 페이징 정보
     * @return 댓글 목록 (페이징)
     */
    Page<PostReadModel> findByParentPostIdOrderByCreatedAtDesc(Long parentPostId, Pageable pageable);
}
