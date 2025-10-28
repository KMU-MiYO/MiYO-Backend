package io.github.herbpot.miyobackend.domain.challenge.exception;

/**
 * ContestNotFoundException
 * - 공모전을 찾을 수 없을 때 발생하는 예외
 * - HTTP 404 Not Found
 */
public class ContestNotFoundException extends RuntimeException {
    public ContestNotFoundException(Long contestId) {
        super("공모전을 찾을 수 없습니다. (contestId: " + contestId + ")");
    }
}
