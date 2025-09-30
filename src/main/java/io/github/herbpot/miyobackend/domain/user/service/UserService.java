package io.github.herbpot.miyobackend.domain.user.service;

import io.github.herbpot.miyobackend.domain.user.dto.request.LoginRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.SignUpRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.UpdateUserRequest;
import io.github.herbpot.miyobackend.domain.user.dto.response.TokenResponse;
import io.github.herbpot.miyobackend.domain.user.dto.response.UserInfoResponse;
import io.github.herbpot.miyobackend.domain.user.entity.User;
import io.github.herbpot.miyobackend.domain.user.repository.UserRepository;
import io.github.herbpot.miyobackend.global.jwt.JwtUtil;
import io.github.herbpot.miyobackend.global.mail.EmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;

    @Value("${miyobackend.frontend.password-reset-url}")
    private String frontendPasswordResetUrl;

    // Temporary storage for email verification codes. In a production environment,
    // consider using a more persistent and scalable solution like Redis or a database.
    private final Map<String, String> emailVerificationCodes = new ConcurrentHashMap<>();

    /**
     * 회원가입을 처리합니다.
     * 중복된 사용자 ID를 검증하고, 이메일 인증 코드를 확인한 후, 비밀번호를 인코딩하여 새로운 사용자 정보를 저장합니다.
     * @param request 회원가입 요청 DTO (이메일 인증 코드 포함)
     * @throws IllegalArgumentException 이메일 인증 코드가 유효하지 않은 경우
     */
    @Transactional
    public void signUp(SignUpRequest request) {
        validateDuplicateUserId(request.getUserId());

        // Verify email code
        if (!verifyEmailCode(request.getEmail(), request.getCode())) {
            throw new IllegalArgumentException("유효하지 않거나 만료된 이메일 인증 코드입니다.");
        }

        String encodedPassword = passwordEncoder.encode(request.getPassword());
        User user = request.toEntity(encodedPassword);
        userRepository.save(user);
    }

    /**
     * 로그인을 처리하고 JWT 토큰을 발급합니다.
     * 사용자 ID로 사용자를 찾고, 비밀번호를 검증한 후 토큰을 생성합니다.
     * @param request 로그인 요청 DTO
     * @return 생성된 JWT 토큰을 포함하는 TokenResponse
     * @throws IllegalArgumentException 유효하지 않은 사용자 ID 또는 비밀번호인 경우
     */
    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByUserId(request.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 사용자입니다."));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        String token = jwtUtil.generateToken(user.getUserId());
        return new TokenResponse(token);
    }

    /**
     * 특정 사용자 ID로 사용자 정보를 조회합니다.
     * @param userId 조회할 사용자 ID
     * @return 조회된 사용자 정보를 포함하는 UserInfoResponse
     * @throws IllegalArgumentException 유효하지 않은 사용자 ID인 경우
     */
    public UserInfoResponse findByUserId(String userId) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 사용자입니다."));
        return UserInfoResponse.from(user);
    }

    /**
     * 사용자 정보를 업데이트합니다.
     * @param userId 업데이트할 사용자의 ID
     * @param request 업데이트할 사용자 정보를 포함하는 DTO
     * @throws IllegalArgumentException 유효하지 않은 사용자 ID인 경우
     */
    @Transactional
    public void updateUser(String userId, UpdateUserRequest request) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 사용자입니다."));
        user.update(request);
    }

    /**
     * 사용자 계정을 삭제합니다.
     * @param userId 삭제할 사용자의 ID
     * @throws IllegalArgumentException 유효하지 않은 사용자 ID인 경우
     */
    @Transactional
    public void deleteUser(String userId) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 사용자입니다."));
        userRepository.delete(user);
    }

    /**
     * 이메일 인증 코드를 생성하여 사용자 이메일로 전송합니다.
     * 생성된 코드는 임시로 저장됩니다.
     * @param email 인증 코드를 받을 이메일 주소
     */
    public void sendVerificationCode(String email) {
        // Generate a 6-digit verification code
        String code = String.format("%06d", new Random().nextInt(999999));
        emailVerificationCodes.put(email, code);

        String subject = "MiYO Backend 이메일 인증";
        String text = "귀하의 인증 코드는: " + code + " 입니다. 이 코드는 짧은 시간 동안 유효합니다.";
        emailService.sendEmail(email, subject, text);
    }

    /**
     * 이메일 인증 코드를 확인합니다.
     * 저장된 코드와 사용자가 제공한 코드가 일치하면 코드를 무효화하고 true를 반환합니다.
     * @param email 인증을 요청한 이메일 주소
     * @param code 사용자가 입력한 인증 코드
     * @return 코드가 유효하면 true, 그렇지 않으면 false
     */
    public boolean verifyEmailCode(String email, String code) {
        String storedCode = emailVerificationCodes.get(email);
        if (storedCode != null && storedCode.equals(code)) {
            emailVerificationCodes.remove(email); // Invalidate the code after successful verification
            return true;
        }
        return false;
    }

    /**
     * 이메일 주소를 통해 사용자 ID를 찾아 해당 이메일로 전송합니다.
     * @param email 사용자 ID를 찾을 이메일 주소
     * @throws IllegalArgumentException 유효하지 않은 이메일인 경우
     */
    public void findUserIdByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 이메일입니다."));

        String subject = "MiYO Backend - 귀하의 사용자 ID";
        String text = "귀하의 사용자 ID는: " + user.getUserId() + " 입니다.";
        emailService.sendEmail(email, subject, text);
    }

    /**
     * 비밀번호 재설정 요청을 처리합니다.
     * 재설정 토큰을 생성하고 사용자 엔티티에 저장한 후, 재설정 링크를 포함한 이메일을 사용자에게 전송합니다.
     * @param email 비밀번호 재설정을 요청한 사용자의 이메일 주소
     * @throws IllegalArgumentException 유효하지 않은 이메일인 경우
     */
    @Transactional
    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 이메일입니다."));

        String token = UUID.randomUUID().toString();
        user.createPasswordResetToken(token); // Save token and expiry to User entity
        userRepository.save(user);

        String resetLink = frontendPasswordResetUrl + token;
        String subject = "MiYO Backend - 비밀번호 재설정 요청";
        String text = "비밀번호 재설정 요청을 하셨습니다. 다음 링크를 클릭하여 비밀번호를 재설정해주세요: " + resetLink + "\n이 링크는 1시간 동안 유효합니다.";
        emailService.sendEmail(email, subject, text);
    }

    /**
     * 비밀번호 재설정을 확인하고 새 비밀번호로 업데이트합니다.
     * 제공된 토큰으로 사용자를 찾고, 토큰의 유효성 및 만료 여부를 확인한 후 비밀번호를 변경합니다.
     * @param token 비밀번호 재설정 토큰
     * @param newPassword 새로 설정할 비밀번호
     * @throws IllegalArgumentException 유효하지 않거나 만료된 재설정 토큰인 경우
     */
    @Transactional
    public void confirmPasswordReset(String token, String newPassword) {
        User user = userRepository.findByPasswordResetToken(token)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않거나 만료된 재설정 토큰입니다."));

        if (user.getPasswordResetTokenExpiryDate() == null || user.getPasswordResetTokenExpiryDate().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("만료된 재설정 토큰입니다.");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.resetPassword(); // Clear token and expiry
        userRepository.save(user);
    }

    /**
     * 사용자 ID의 중복 여부를 검증합니다.
     * @param userId 검증할 사용자 ID
     * @throws IllegalStateException 이미 존재하는 사용자 ID인 경우
     */
    private void validateDuplicateUserId(String userId) {
        userRepository.findByUserId(userId)
                .ifPresent(user -> {
                    throw new IllegalStateException("이미 존재하는 아이디입니다.");
                });
    }
}
