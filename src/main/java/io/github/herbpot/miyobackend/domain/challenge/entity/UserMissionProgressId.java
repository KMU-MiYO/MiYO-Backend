package io.github.herbpot.miyobackend.domain.challenge.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.*;

import java.io.Serializable;

/**
 * UserMissionProgress Composite Primary Key
 * - 유저별 미션 진행 현황의 복합키 (mission_id, user_id)
 */
@Embeddable
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@EqualsAndHashCode
public class UserMissionProgressId implements Serializable {

    /**
     * 미션 ID
     */
    @Column(name = "mission_id")
    private Long missionId;

    /**
     * 유저 ID
     */
    @Column(name = "user_id", length = 255)
    private String userId;
}
