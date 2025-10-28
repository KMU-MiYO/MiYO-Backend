package io.github.herbpot.miyobackend.domain.user.controller;

import io.github.herbpot.miyobackend.domain.user.dto.request.LoginRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.SignUpRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.UpdateUserRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.EmailVerificationRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.EmailVerificationConfirmRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.FindIdRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.PasswordResetRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.PasswordResetConfirmRequest;
import io.github.herbpot.miyobackend.domain.user.dto.response.ExistsResponse;
import io.github.herbpot.miyobackend.domain.user.dto.response.TokenResponse;
import io.github.herbpot.miyobackend.domain.user.dto.response.UserInfoResponse;
import io.github.herbpot.miyobackend.domain.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Tag(name = "User", description = "사용자 관리 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserRestController {

    private final UserService userService;

    @Operation(
            summary = "회원 가입",
            description = "새로운 사용자를 등록합니다. 닉네임, 아이디, 이메일, 비밀번호는 필수이며, 프로필 이미지는 선택사항입니다."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "회원 가입 성공"),
            @ApiResponse(responseCode = "400", description = "잘못된 요청 (중복된 아이디/이메일 등)", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @PostMapping(value = "/signup", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Void> signUp(@ModelAttribute SignUpRequest request) {
        userService.signUp(request);
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "로그인",
            description = "사용자 아이디와 비밀번호로 로그인하여 JWT 액세스 토큰을 발급받습니다."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "로그인 성공, JWT 토큰 반환",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = TokenResponse.class),
                            examples = @ExampleObject(
                                    value = "{\"accessToken\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\"}"
                            )
                    )
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패 (잘못된 아이디 또는 비밀번호)", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {
        TokenResponse token = userService.login(request);
        return ResponseEntity.ok(token);
    }

    @Operation(
            summary = "사용자 정보 조회",
            description = "특정 사용자의 상세 정보를 조회합니다. JWT 토큰이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserInfoResponse.class),
                            examples = @ExampleObject(
                                    value = "{\"nickname\": \"홍길동\", \"userId\": \"hong123\", \"email\": \"hong@example.com\", \"profilePicture\": \"https://example.com/profile.jpg\", \"createdAt\": \"2025-01-15T10:30:00\"}"
                            )
                    )
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패 (토큰 없음 또는 유효하지 않음)", content = @Content),
            @ApiResponse(responseCode = "404", description = "사용자를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @GetMapping("/{userId}")
    public ResponseEntity<UserInfoResponse> findByUserId(
            @Parameter(description = "조회할 사용자 아이디", example = "hong123")
            @PathVariable String userId
    ) {
        UserInfoResponse response = userService.findByUserId(userId);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "사용자 정보 수정",
            description = "사용자의 닉네임 및 프로필 이미지를 수정합니다. JWT 토큰이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "수정 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패 (토큰 없음 또는 유효하지 않음)", content = @Content),
            @ApiResponse(responseCode = "403", description = "권한 없음 (본인이 아닌 경우)", content = @Content),
            @ApiResponse(responseCode = "404", description = "사용자를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @PatchMapping(value = "/{userId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Void> updateUser(
            @Parameter(description = "수정할 사용자 아이디", example = "hong123")
            @PathVariable String userId,
            @ModelAttribute UpdateUserRequest request
    ) {
        userService.updateUser(userId, request);
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "계정 삭제",
            description = "사용자 계정을 삭제합니다. JWT 토큰이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "삭제 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패 (토큰 없음 또는 유효하지 않음)", content = @Content),
            @ApiResponse(responseCode = "403", description = "권한 없음 (본인이 아닌 경우)", content = @Content),
            @ApiResponse(responseCode = "404", description = "사용자를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(
            @Parameter(description = "삭제할 사용자 아이디", example = "hong123")
            @PathVariable String userId
    ) {
        userService.deleteUser(userId);
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "이메일 인증코드 요청",
            description = "회원가입 시 이메일 인증을 위한 인증코드를 요청합니다. 입력한 이메일로 인증코드가 발송됩니다."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "인증코드 발송 성공"),
            @ApiResponse(responseCode = "400", description = "잘못된 이메일 형식", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @PostMapping("/email-verification-request")
    public ResponseEntity<Void> requestEmailVerification(@RequestBody EmailVerificationRequest request) {
        userService.sendVerificationCode(request.getEmail());
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "이메일 인증코드 확인",
            description = "발송된 이메일 인증코드를 확인합니다. 인증 성공 시 회원가입을 진행할 수 있습니다."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "인증 성공"),
            @ApiResponse(
                    responseCode = "400",
                    description = "인증 실패 (유효하지 않거나 만료된 인증코드)",
                    content = @Content(
                            mediaType = "text/plain",
                            examples = @ExampleObject(value = "유효하지 않거나 만료된 이메일 인증 코드입니다.")
                    )
            ),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @PostMapping("/email-verification-confirm")
    public ResponseEntity<Void> confirmEmailVerification(@RequestBody EmailVerificationConfirmRequest request) {
        userService.verifyEmailCode(request.getEmail(), request.getCode());
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "아이디 찾기",
            description = "이메일 주소로 가입된 사용자의 아이디를 찾습니다. 해당 이메일로 아이디 정보가 발송됩니다."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "아이디 찾기 요청 성공 (이메일 발송됨)"),
            @ApiResponse(responseCode = "404", description = "해당 이메일로 가입된 사용자를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @PostMapping("/find-id")
    public ResponseEntity<Void> findId(@RequestBody FindIdRequest request) {
        userService.findUserIdByEmail(request.getEmail());
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "비밀번호 재설정 요청",
            description = "비밀번호를 재설정하기 위한 링크를 이메일로 발송합니다. 이메일에 포함된 링크를 통해 비밀번호를 재설정할 수 있습니다."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "비밀번호 재설정 링크 발송 성공"),
            @ApiResponse(responseCode = "404", description = "해당 이메일로 가입된 사용자를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @PostMapping("/password-reset-request")
    public ResponseEntity<Void> requestPasswordReset(@RequestBody PasswordResetRequest request) {
        userService.requestPasswordReset(request.getEmail());
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "비밀번호 재설정 확인",
            description = "이메일로 받은 토큰을 사용하여 새로운 비밀번호로 변경합니다."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "비밀번호 재설정 성공"),
            @ApiResponse(
                    responseCode = "403",
                    description = "비밀번호 재설정 실패 (유효하지 않거나 만료된 토큰)",
                    content = @Content(
                            mediaType = "text/plain",
                            examples = @ExampleObject(value = "유효하지 않거나 만료된 토큰입니다.")
                    )
            ),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @PostMapping("/password-reset-confirm")
    public ResponseEntity<Void> confirmPasswordReset(
            @Parameter(description = "이메일로 받은 비밀번호 재설정 토큰", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
            @RequestParam String token,
            @RequestBody PasswordResetConfirmRequest request
    ) {
        userService.confirmPasswordReset(token, request.getNewPassword());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/isExists/{userId}")
    public ResponseEntity<ExistsResponse> isExists(@PathVariable String userId) {
        return ResponseEntity.ok(userService.isIdExist(userId));
    }

    @GetMapping("/myId")
    public ResponseEntity<UserInfoResponse> myId() {
        UserInfoResponse res = userService.findByUserId(userService.getCurrentUserId());
        return ResponseEntity.ok(res);
    }
}
