package io.github.herbpot.miyobackend.domain.community.repository.write;

import io.github.herbpot.miyobackend.domain.community.entity.Post;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * PostRepository (Write Model Repository)
 * - posts_write 테이블에 대한 JPA Repository
 * - Write DB 사용
 * - 게시글 작성, 삭제 등의 쓰기 작업 처리
 */
@Repository
public interface PostRepository extends JpaRepository<Post, Long> {

    /**
     * 게시글 ID와 작성자 ID로 조회
     * - 삭제 시 본인 확인용
     *
     * @param postId 게시글 ID
     * @param userId 작성자 ID
     * @return 조건에 맞는 게시글
     */
    @Query("SELECT p FROM Post p WHERE p.postId = :postId AND p.userId = :userId")
    Optional<Post> findByPostIdAndUserId(@Param("postId") Long postId, @Param("userId") String userId);
}
