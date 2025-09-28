package io.github.herbpot.miyobackend.domain.user.controller;

import io.github.herbpot.miyobackend.domain.user.dto.request.LoginRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.SignUpRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.UpdateUserRequest;
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
}
