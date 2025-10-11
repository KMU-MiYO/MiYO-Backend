package io.github.herbpot.miyobackend.domain.user.repository_test_folder;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

/**
 * UserRepositoryImpl
 * - UserRepository의 구현체
 * - EntityManager를 사용하여 Native Query 실행
 */
@Slf4j
@Repository
public class UserRepositoryImpl implements UserRepository {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * 사용자 ID로 닉네임 조회
     *
     * @param id 사용자 ID
     * @return 닉네임 (없으면 null)
     */
    @Override
    public String findNicknameById(Long id) {
        try {
            String sql = "SELECT nickname FROM user WHERE id = :id";
            return (String) entityManager.createNativeQuery(sql)
                    .setParameter("id", id)
                    .getSingleResult();
        } catch (Exception e) {
            log.warn("Failed to find nickname for userId={}: {}", id, e.getMessage());
            return null;
        }
    }
}
