package io.github.herbpot.miyobackend.domain.challenge.exception;

/**
 * AlreadySubmittedException
 * - 이미 제출한 공모전에 중복 제출을 시도할 때 발생하는 예외
 * - HTTP 409 Conflict
 */
public class AlreadySubmittedException extends RuntimeException {
    public AlreadySubmittedException(Long contestId, String userId) {
        super("이미 제출한 공모전입니다. (contestId: " + contestId + ", userId: " + userId + ")");
    }
}
