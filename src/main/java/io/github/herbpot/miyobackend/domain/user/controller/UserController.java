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
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserController {

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

    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        // For JWT, client-side token removal is usually sufficient.
        // If server-side token invalidation (e.g., blacklisting) is required,
        // additional logic would be added here.
        return ResponseEntity.ok().build();
    }

    @PostMapping("/email-verification-request")
    public ResponseEntity<Void> requestEmailVerification(@RequestBody EmailVerificationRequest request) {
        userService.sendVerificationCode(request.getEmail());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/email-verification-confirm")
    public ResponseEntity<Void> confirmEmailVerification(@RequestBody EmailVerificationConfirmRequest request) {
        if (userService.verifyEmailCode(request.getEmail(), request.getCode())) {
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.badRequest().build();
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
    public ResponseEntity<Void> confirmPasswordReset(@RequestParam String token, @RequestBody PasswordResetConfirmRequest request) {
        userService.confirmPasswordReset(token, request.getNewPassword());
        return ResponseEntity.ok().build();
    }
}
