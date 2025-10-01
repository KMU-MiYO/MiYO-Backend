package io.github.herbpot.miyobackend.domain.user.entity;

import io.github.herbpot.miyobackend.config.Authoriy;
import io.github.herbpot.miyobackend.domain.user.dto.request.UpdateUserRequest;
import jakarta.persistence.*;
import lombok.*;

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

    @Enumerated(EnumType.STRING)
    private Authoriy authority;

    public static User of(String nickname, String userId, String email, String password, String profilePicture, Authoriy authority) {
        return new User(null, nickname, userId, email, password, profilePicture, LocalDateTime.now(), null, null, authority);
    }

    public void update(UpdateUserRequest request) {
        if (request.getNickname() != null) {
            this.nickname = request.getNickname();
        }
    }

    public void updateProfileImageUrl(String profileImageUrl) {
        this.profilePicture = profileImageUrl;
    }

    public void createPasswordResetToken(String token, LocalDateTime expireDate) {
        this.passwordResetToken = token;
        this.passwordResetTokenExpiryDate = expireDate; // Token valid for 1 hour
    }

    public void resetPassword() {
        this.passwordResetToken = null;
        this.passwordResetTokenExpiryDate = null;
    }

}
