package io.github.herbpot.miyobackend.domain.user.repository_test_folder;

/**
 * UserRepository
 * - user 테이블에 대한 Repository 인터페이스
 * - 사용자 닉네임 조회만 지원 (User 도메인은 다른 브랜치에서 개발 중)
 */
public interface UserRepository {

    /**
     * 사용자 ID로 닉네임 조회
     *
     * @param id 사용자 ID
     * @return 닉네임 (없으면 null)
     */
    String findNicknameById(Long id);
}
