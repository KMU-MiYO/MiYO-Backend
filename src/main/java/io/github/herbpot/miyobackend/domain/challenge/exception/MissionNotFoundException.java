package io.github.herbpot.miyobackend.domain.challenge.exception;

/**
 * MissionNotFoundException
 * - 미션을 찾을 수 없을 때 발생하는 예외
 * - HTTP 404 Not Found
 */
public class MissionNotFoundException extends RuntimeException {
    public MissionNotFoundException(Long missionId) {
        super("미션을 찾을 수 없습니다. (missionId: " + missionId + ")");
    }
}
