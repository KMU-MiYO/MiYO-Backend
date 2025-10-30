package io.github.herbpot.miyobackend.domain.community.event;

import lombok.Getter;

/**
 * MissionEvent
 * - Spring ApplicationEvent를 통해 전송되는 미션 관련 이벤트
 * - Posts 도메인에서 발행하여 Mission 도메인에서 구독
 * - Mission 진행도 업데이트를 위한 이벤트
 */
@Getter
public class MissionEvent {

    /**
     * 미션 액션 타입
     * - proposal: 제안서 작성
     * - empathy: 공감(좋아요) 누르기
     * - comment: 댓글 작성
     */
    public enum ActionType {
        PROPOSAL,   // 게시글 작성
        EMPATHY,    // 공감 누르기
        COMMENT     // 댓글 작성
    }

    /**
     * 사용자 ID
     */
    private final String userId;

    /**
     * 관련 엔티티 ID (postId, empathyId, commentId 등)
     */
    private final Long relatedId;

    /**
     * 액션 타입
     */
    private final ActionType actionType;

    /**
     * 생성자
     *
     * @param userId 사용자 ID
     * @param relatedId 관련 엔티티 ID
     * @param actionType 액션 타입
     */
    public MissionEvent(String userId, Long relatedId, ActionType actionType) {
        this.userId = userId;
        this.relatedId = relatedId;
        this.actionType = actionType;
    }

    /**
     * 제안서(게시글) 작성 이벤트 생성
     */
    public static MissionEvent ofProposal(String userId, Long postId) {
        return new MissionEvent(userId, postId, ActionType.PROPOSAL);
    }

    /**
     * 공감 이벤트 생성
     */
    public static MissionEvent ofEmpathy(String userId, Long empathyId) {
        return new MissionEvent(userId, empathyId, ActionType.EMPATHY);
    }

    /**
     * 댓글 이벤트 생성
     */
    public static MissionEvent ofComment(String userId, Long commentId) {
        return new MissionEvent(userId, commentId, ActionType.COMMENT);
    }

    /**
     * Mission Validator에서 사용할 category 문자열 반환
     *
     * @return "proposal", "empathy", "comment"
     */
    public String getCategoryString() {
        return actionType.name().toLowerCase();
    }
}
