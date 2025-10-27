package io.github.herbpot.miyobackend.domain.challenge.validator;

/**
 * MissionValidator Interface
 * - Strategy Pattern의 인터페이스
 * - 미션 종류별 검증 로직을 구현
 * - 각 미션 타입(제안, 공감, 댓글 등)에 대한 검증자가 이 인터페이스를 구현
 */
public interface MissionValidator {

    /**
     * 미션 카테고리 반환
     * - 이 검증자가 처리할 수 있는 미션 카테고리
     *
     * @return 미션 카테고리 (예: "proposal", "empathy", "comment")
     */
    String getCategory();

    /**
     * 미션 진행 검증 및 진행도 업데이트
     * - 사용자가 특정 행동을 수행했을 때 해당 미션의 진행도를 업데이트
     * - 예: 제안 작성 시 제안 미션 진행도 +1
     *
     * @param userId 사용자 ID
     * @param relatedId 관련 엔티티 ID (게시글 ID, 공모전 ID 등)
     */
    void validateAndUpdateProgress(String userId, Long relatedId);
}
