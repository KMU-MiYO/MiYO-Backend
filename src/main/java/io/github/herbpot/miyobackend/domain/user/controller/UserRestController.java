package io.github.herbpot.miyobackend.domain.user.controller;

import io.github.herbpot.miyobackend.domain.user.dto.request.LoginRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.SignUpRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.UpdateUserRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.EmailVerificationRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.EmailVerificationConfirmRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.FindIdRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.PasswordResetRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.PasswordResetConfirmRequest;
import io.github.herbpot.miyobackend.domain.user.dto.response.TokenResponse;
import io.github.herbpot.miyobackend.domain.user.dto.response.UserInfoResponse;
import io.github.herbpot.miyobackend.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserRestController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<Void> signUp(@RequestBody SignUpRequest request) {
        userService.signUp(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {
        TokenResponse token = userService.login(request);
        return ResponseEntity.ok(token);
    }

    @GetMapping("/{userId}")
    public ResponseEntity<UserInfoResponse> findByUserId(@PathVariable String userId) {
        UserInfoResponse response = userService.findByUserId(userId);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/{userId}")
    public ResponseEntity<Void> updateUser(@PathVariable String userId, @RequestBody UpdateUserRequest request) {
        userService.updateUser(userId, request);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable String userId) {
        userService.deleteUser(userId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/email-verification-request")
    public ResponseEntity<Void> requestEmailVerification(@RequestBody EmailVerificationRequest request) {
        userService.sendVerificationCode(request.getEmail());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/email-verification-confirm")
    public ResponseEntity<String> confirmEmailVerification(@RequestBody EmailVerificationConfirmRequest request) {
        if (userService.verifyEmailCode(request.getEmail(), request.getCode())) {
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.badRequest().body("유효하지 않거나 만료된 이메일 인증 코드입니다.");
        }
    }

    @PostMapping("/find-id")
    public ResponseEntity<Void> findId(@RequestBody FindIdRequest request) {
        userService.findUserIdByEmail(request.getEmail());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password-reset-request")
    public ResponseEntity<Void> requestPasswordReset(@RequestBody PasswordResetRequest request) {
        userService.requestPasswordReset(request.getEmail());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password-reset-confirm")
    public ResponseEntity<String> confirmPasswordReset(@RequestParam String token, @RequestBody PasswordResetConfirmRequest request) {
        try{
            userService.confirmPasswordReset(token, request.getNewPassword());
            return ResponseEntity.ok().build();
        }catch(IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        }
    }
}
