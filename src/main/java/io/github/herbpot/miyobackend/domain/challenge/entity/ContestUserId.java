package io.github.herbpot.miyobackend.domain.challenge.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.*;

import java.io.Serializable;

/**
 * ContestUser Composite Primary Key
 * - 공모전 참가자의 복합키 (contest_id, user_id)
 */
@Embeddable
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@EqualsAndHashCode
public class ContestUserId implements Serializable {

    /**
     * 공모전 ID
     */
    @Column(name = "contest_id")
    private Long contestId;

    /**
     * 유저 ID
     */
    @Column(name = "user_id", length = 255)
    private String userId;
}
