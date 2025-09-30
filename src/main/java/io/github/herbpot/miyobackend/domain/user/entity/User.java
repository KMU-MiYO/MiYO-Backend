package io.github.herbpot.miyobackend.domain.user.entity;

import io.github.herbpot.miyobackend.domain.user.dto.request.UpdateUserRequest;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String nickname;

    @Column(unique = true, nullable = false)
    private String userId;

    @Column(nullable = false)
    private String email;

    @Setter
    @Column(nullable = false)
    private String password;

    private String profilePicture;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    private String passwordResetToken;

    private LocalDateTime passwordResetTokenExpiryDate;

    public static User of(String nickname, String userId, String email, String password, String profilePicture) {
        return new User(null, nickname, userId, email, password, profilePicture, LocalDateTime.now(), null, null);
    }

    public void update(UpdateUserRequest request) {
        if (request.getNickname() != null) {
            this.nickname = request.getNickname();
        }
        if (request.getProfilePicture() != null) {
            this.profilePicture = request.getProfilePicture();
        }
    }

    public void createPasswordResetToken(String token) {
        this.passwordResetToken = token;
        this.passwordResetTokenExpiryDate = LocalDateTime.now().plusHours(1); // Token valid for 1 hour
    }

    public void resetPassword() {
        this.passwordResetToken = null;
        this.passwordResetTokenExpiryDate = null;
    }

}
