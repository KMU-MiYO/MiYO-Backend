package io.github.herbpot.miyobackend.domain.user.entity;

import io.github.herbpot.miyobackend.domain.user.dto.request.UpdateUserRequest;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

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

    @Column(nullable = false)
    private String password;

    private String profilePicture;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    public static User of(String nickname, String userId, String email, String password, String profilePicture) {
        return new User(null, nickname, userId, email, password, profilePicture, LocalDateTime.now());
    }

    public void update(UpdateUserRequest request) {
        if (request.getNickname() != null) {
            this.nickname = request.getNickname();
        }
        if (request.getProfilePicture() != null) {
            this.profilePicture = request.getProfilePicture();
        }
    }
}
