package io.github.herbpot.miyobackend.domain.community.entity.write;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor()
public class RewardModel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column
    public String id;

    @Column
    public String userId;

    @Column
    public Integer reward;

    @Builder
    public RewardModel(String userId, Integer reward) {
        this.userId = userId;
        this.reward = reward;
    }

}
