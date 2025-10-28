package io.github.herbpot.miyobackend.domain.challenge.exception;

/**
 * AlreadyJoinedException
 * - 이미 참가한 공모전에 중복 참가를 시도할 때 발생하는 예외
 * - HTTP 409 Conflict
 */
public class AlreadyJoinedException extends RuntimeException {
    public AlreadyJoinedException(Long contestId, String userId) {
        super("이미 참가한 공모전입니다. (contestId: " + contestId + ", userId: " + userId + ")");
    }
}
