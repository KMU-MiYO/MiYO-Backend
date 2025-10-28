package io.github.herbpot.miyobackend.domain.community.repository.write;

import io.github.herbpot.miyobackend.domain.community.entity.write.EmpathyData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * EmpathyRepository (Write DB)
 * - empathy_data 테이블에 대한 JPA Repository
 * - Write DB 사용
 * - 공감 추가, 삭제
 */
@Repository
public interface EmpathyRepository extends JpaRepository<EmpathyData, Long> {

    /**
     * 사용자의 특정 게시글 공감 조회
     *
     * @param userId 사용자 ID
     * @param postId 게시글 ID
     * @return 공감 데이터
     */
    Optional<EmpathyData> findByUserIdAndPostId(String userId, Long postId);

    /**
     * 사용자가 특정 게시글에 공감했는지 확인
     *
     * @param userId 사용자 ID
     * @param postId 게시글 ID
     * @return 공감 여부
     */
    boolean existsByUserIdAndPostId(String userId, Long postId);
}
