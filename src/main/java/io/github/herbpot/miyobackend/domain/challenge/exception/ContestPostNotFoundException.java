package io.github.herbpot.miyobackend.domain.challenge.exception;

/**
 * ContestPostNotFoundException
 * - 제출물을 찾을 수 없을 때 발생하는 예외
 * - HTTP 404 Not Found
 */
public class ContestPostNotFoundException extends RuntimeException {
    public ContestPostNotFoundException(Long postId) {
        super("제출물을 찾을 수 없습니다. (postId: " + postId + ")");
    }
}
