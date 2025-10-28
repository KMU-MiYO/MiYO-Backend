package io.github.herbpot.miyobackend.global.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {
    private final int status;
    private final String error;
    private final String message;
    private final LocalDateTime timestamp;
    private final String path;
    private final List<FieldError> errors;

    @Getter
    @Builder
    public static class FieldError {
        private final String field;
        private final String value;
        private final String reason;
    }

    public static ErrorResponse of(ErrorCode errorCode, String path) {
        return ErrorResponse.builder()
                .status(errorCode.getStatus().value())
                .error(errorCode.getStatus().name())
                .message(errorCode.getMessage())
                .timestamp(LocalDateTime.now())
                .path(path)
                .build();
    }

    public static ErrorResponse of(HttpStatus status, String message, String path) {
        return ErrorResponse.builder()
                .status(status.value())
                .error(status.name())
                .message(message)
                .timestamp(LocalDateTime.now())
                .path(path)
                .build();
    }

    public static ErrorResponse of(HttpStatus status, String message, String path, List<FieldError> errors) {
        return ErrorResponse.builder()
                .status(status.value())
                .error(status.name())
                .message(message)
                .timestamp(LocalDateTime.now())
                .path(path)
                .errors(errors)
                .build();
    }
}
