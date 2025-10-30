package io.github.herbpot.miyobackend.domain.community.validator;

/**
 * MissionValidator
 * - Strategy 패턴의 인터페이스
 * - 각 액션 타입(proposal, empathy, comment)에 대한 미션 검증 및 진행도 업데이트
 */
public interface MissionValidator {

    /**
     * 이 Validator가 처리하는 카테고리 반환
     *
     * @return "proposal", "empathy", "comment"
     */
    String getCategory();

    /**
     * 미션 검증 및 진행도 업데이트
     *
     * @param userId 사용자 ID
     * @param relatedId 관련 엔티티 ID (postId, empathyId, commentId)
     */
    void validateAndUpdateProgress(String userId, Long relatedId);
}
