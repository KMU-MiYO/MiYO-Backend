package io.github.herbpot.miyobackend.domain.challenge.exception;

/**
 * NotParticipantException
 * - 공모전에 참가하지 않은 사용자가 제출물을 작성하려 할 때 발생하는 예외
 * - HTTP 403 Forbidden
 */
public class NotParticipantException extends RuntimeException {
    public NotParticipantException(Long contestId, String userId) {
        super("공모전에 참가하지 않았습니다. (contestId: " + contestId + ", userId: " + userId + ")");
    }
}
