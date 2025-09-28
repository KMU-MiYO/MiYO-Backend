package io.github.herbpot.miyobackend.domain.user.service;

import io.github.herbpot.miyobackend.domain.user.dto.request.LoginRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.SignUpRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.UpdateUserRequest;
import io.github.herbpot.miyobackend.domain.user.dto.response.TokenResponse;
import io.github.herbpot.miyobackend.domain.user.dto.response.UserInfoResponse;
import io.github.herbpot.miyobackend.domain.user.entity.User;
import io.github.herbpot.miyobackend.domain.user.repository.UserRepository;
import io.github.herbpot.miyobackend.global.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @Transactional
    public void signUp(SignUpRequest request) {
        validateDuplicateUserId(request.getUserId());
        String encodedPassword = passwordEncoder.encode(request.getPassword());
        User user = request.toEntity(encodedPassword);
        userRepository.save(user);
    }

    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByUserId(request.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("�������� �ʴ� ������Դϴ�."));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("��й�ȣ�� ��ġ���� �ʽ��ϴ�.");
        }

        String token = jwtUtil.generateToken(user.getUserId());
        return new TokenResponse(token);
    }

    public UserInfoResponse findByUserId(String userId) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new IllegalArgumentException("�������� �ʴ� ������Դϴ�."));
        return UserInfoResponse.from(user);
    }

    @Transactional
    public void updateUser(String userId, UpdateUserRequest request) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new IllegalArgumentException("�������� �ʴ� ������Դϴ�."));
        user.update(request);
    }

    @Transactional
    public void deleteUser(String userId) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new IllegalArgumentException("�������� �ʴ� ������Դϴ�."));
        userRepository.delete(user);
    }

    private void validateDuplicateUserId(String userId) {
        userRepository.findByUserId(userId)
                .ifPresent(user -> {
                    throw new IllegalStateException("�̹� �����ϴ� ���̵��Դϴ�.");
                });
    }
}
