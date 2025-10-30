package io.github.herbpot.miyobackend.global.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    // 400 Bad Request
    INVALID_INPUT_VALUE(HttpStatus.BAD_REQUEST, "잘못된 입력값입니다."),
    INVALID_TYPE_VALUE(HttpStatus.BAD_REQUEST, "잘못된 타입입니다."),
    INVALID_EMAIL_CODE(HttpStatus.BAD_REQUEST, "유효하지 않거나 만료된 이메일 인증 코드입니다."),

    // 401 Unauthorized
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "인증이 필요합니다."),
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다."),
    EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "만료된 토큰입니다."),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "잘못된 아이디 또는 비밀번호입니다."),

    // 403 Forbidden
    FORBIDDEN(HttpStatus.FORBIDDEN, "권한이 없습니다."),
    INVALID_RESET_TOKEN(HttpStatus.FORBIDDEN, "유효하지 않거나 만료된 토큰입니다."),

    // 404 Not Found
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."),
    RESOURCE_NOT_FOUND(HttpStatus.NOT_FOUND, "요청한 리소스를 찾을 수 없습니다."),
    BADGE_NOT_FOUND(HttpStatus.NOT_FOUND, "뱃지를 찾을 수 없습니다."),
    USER_BADGE_NOT_FOUND(HttpStatus.NOT_FOUND, "사용자가 해당 뱃지를 보유하고 있지 않습니다."),

    // 409 Conflict
    DUPLICATE_USER_ID(HttpStatus.CONFLICT, "이미 존재하는 아이디입니다."),
    DUPLICATE_EMAIL(HttpStatus.CONFLICT, "이미 사용 중인 이메일입니다."),
    DUPLICATE_RESOURCE(HttpStatus.CONFLICT, "이미 존재하는 리소스입니다."),
    BADGE_ALREADY_ASSIGNED(HttpStatus.CONFLICT, "이미 보유한 뱃지입니다."),

    // 500 Internal Server Error
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버 내부 오류가 발생했습니다."),
    FILE_UPLOAD_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "파일 업로드 중 오류가 발생했습니다."),
    EMAIL_SEND_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "이메일 전송 중 오류가 발생했습니다.");

    private final HttpStatus status;
    private final String message;
}
