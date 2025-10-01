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
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Random;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private final RedisTemplate<String, String> redisTemplate;

    @Value("${miyobackend.frontend.password-reset-url}")
    private String frontendPasswordResetUrl;

    @Value("${miyobackend.redis.user-deletation-channel}")
    private String REDIS_USER_DELETATION_CHANNEL;

    // 상수 관리
    private static final String EMAIL_VERIFICATION_SUBJECT = "MiYO Backend 이메일 인증";
    private static final String FIND_USER_ID_SUBJECT = "MiYO Backend - 귀하의 사용자 ID";
    private static final String PASSWORD_RESET_SUBJECT = "MiYO Backend - 비밀번호 재설정 요청";

    // Redis Key Prefix
    private static final String REDIS_VERIFICATION_CODE_PREFIX = "email-verification-code:";
    private static final String REDIS_VERIFIED_EMAIL_PREFIX = "verified-email:"; // 인증 완료 상태 저장용

    // 유효 시간
    private static final long EMAIL_VERIFICATION_CODE_EXPIRATION_MINUTES = 5; // 인증 코드 유효 시간 (5분)
    private static final long EMAIL_VERIFIED_STATUS_EXPIRATION_MINUTES = 30; // 인증 완료 상태 유효 시간 (30분)
    private static final int PASSWORD_RESET_TOKEN_EXPIRATION_HOURS = 1;

    /**
     * 회원가입을 처리합니다.
     * 이메일 인증이 완료되었는지 확인한 후, 중복 ID 검사를 거쳐 사용자를 저장합니다.
     * @param request 회원가입 요청 DTO (인증 코드 제외)
     * @throws IllegalStateException 이메일 인증이 완료되지 않았거나 만료된 경우
     */
    @Transactional
    public void signUp(SignUpRequest request) {
        // 1. 이메일 인증 상태부터 확인
        checkAndInvalidateEmailVerificationStatus(request.getEmail());

        // 2. 사용자 ID 중복 검증
        validateDuplicateUserId(request.getUserId());

        // 3. 사용자 등록
        String encodedPassword = passwordEncoder.encode(request.getPassword());
        User user = request.toEntity(encodedPassword);
        userRepository.save(user);
    }

    /**
     * 이메일 인증 코드를 확인하고, 성공 시 '인증 완료' 상태를 Redis에 저장합니다.
     * @param email 인증을 요청한 이메일 주소
     * @param code 사용자가 입력한 인증 코드
     * @throws IllegalArgumentException 제공된 인증 코드가 유효하지 않은 경우
     */
    public Boolean verifyEmailCode(String email, String code) {
        String redisCodeKey = REDIS_VERIFICATION_CODE_PREFIX + email;
        String storedCode = redisTemplate.opsForValue().get(redisCodeKey);

        if (storedCode == null | !storedCode.equals(code)) {
            return false;
        }

        // 인증 성공 시, '인증 완료' 상태를 Redis에 저장 (30분 유효)
        String redisVerifiedKey = REDIS_VERIFIED_EMAIL_PREFIX + email;
        redisTemplate.opsForValue().set(redisVerifiedKey, "true", Duration.ofMinutes(EMAIL_VERIFIED_STATUS_EXPIRATION_MINUTES));
        redisTemplate.delete(redisCodeKey); // 사용된 인증 코드는 즉시 삭제
        return true;
    }

    /**
     * 회원가입 시 이메일이 인증되었는지 확인하고, 확인 후에는 인증 상태를 무효화(삭제)합니다.
     * @param email 확인할 이메일 주소
     * @throws IllegalStateException 이메일 인증이 완료되지 않았거나 만료된 경우
     */
    private void checkAndInvalidateEmailVerificationStatus(String email) {
        String redisVerifiedKey = REDIS_VERIFIED_EMAIL_PREFIX + email;
        String status = redisTemplate.opsForValue().get(redisVerifiedKey);

        if (!"true".equals(status)) {
            throw new IllegalStateException("이메일 인증이 필요합니다.");
        }

        redisTemplate.delete(redisVerifiedKey); // 회원가입에 사용된 인증 상태는 즉시 삭제
    }

    // --- 이하 다른 메소드들은 이전과 동일 ---

    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByUserId(request.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("아이디 또는 비밀번호가 올바르지 않습니다."));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("아이디 또는 비밀번호가 올바르지 않습니다.");
        }

        String token = jwtUtil.generateToken(user.getUserId());
        return new TokenResponse(token);
    }

    public UserInfoResponse findByUserId(String userId) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 사용자입니다."));
        return UserInfoResponse.from(user);
    }

    @Transactional
    public void updateUser(String userId, UpdateUserRequest request) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 사용자입니다."));
        user.update(request);
    }

    @Transactional
    public void deleteUser(String userId) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 사용자입니다."));
        userRepository.delete(user);

        redisTemplate.convertAndSend(REDIS_USER_DELETATION_CHANNEL, userId);
    }

    public void sendVerificationCode(String email) {
        String code = String.format("%06d", new Random().nextInt(999999));
        String redisKey = REDIS_VERIFICATION_CODE_PREFIX + email;

        redisTemplate.opsForValue().set(redisKey, code, Duration.ofMinutes(EMAIL_VERIFICATION_CODE_EXPIRATION_MINUTES));

        String text = "귀하의 인증 코드는: " + code + " 입니다. 이 코드는 " + EMAIL_VERIFICATION_CODE_EXPIRATION_MINUTES + "분 동안 유효합니다.";
        emailService.sendEmail(email, EMAIL_VERIFICATION_SUBJECT, text);
    }

    public void findUserIdByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 이메일입니다."));

        String text = "귀하의 사용자 ID는: " + user.getUserId() + " 입니다.";
        emailService.sendEmail(email, FIND_USER_ID_SUBJECT, text);
    }

    @Transactional
    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 이메일입니다."));

        String token = generateSecureToken();
        LocalDateTime expiryDate = LocalDateTime.now().plusHours(PASSWORD_RESET_TOKEN_EXPIRATION_HOURS);
        user.createPasswordResetToken(token, expiryDate);
        userRepository.save(user);

        String resetLink = frontendPasswordResetUrl + token;
        String text = "비밀번호 재설정 요청을 하셨습니다. 다음 링크를 클릭하여 비밀번호를 재설정해주세요: " +
                "<a href=" + resetLink + ">링크</a>" +
                "\n이 링크는 " + PASSWORD_RESET_TOKEN_EXPIRATION_HOURS + "시간 동안 유효합니다.";
        emailService.sendEmail(email, PASSWORD_RESET_SUBJECT, text);
    }

    @Transactional
    public void confirmPasswordReset(String token, String newPassword) {
        User user = userRepository.findByPasswordResetToken(token)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않거나 만료된 재설정 토큰입니다."));

        if (user.getPasswordResetTokenExpiryDate() == null || user.getPasswordResetTokenExpiryDate().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("만료된 재설정 토큰입니다.");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.resetPassword();
        userRepository.save(user);
    }

    private void validateDuplicateUserId(String userId) {
        if (userRepository.existsByUserId(userId)) {
            throw new IllegalStateException("이미 존재하는 아이디입니다.");
        }
    }

    private String generateSecureToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}