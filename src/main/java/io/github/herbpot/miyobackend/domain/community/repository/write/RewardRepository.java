package io.github.herbpot.miyobackend.domain.community.repository.write;

import io.github.herbpot.miyobackend.domain.community.entity.write.RewardModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface RewardRepository extends JpaRepository<RewardModel, String> {

    Optional<RewardModel> findByUserId(String userId);
    Boolean existsByUserId(String userId);

    @Modifying
    @Transactional("writeTransactionManager")
    @Query("update RewardModel r set r.reward = r.reward+1 where r.userId=?1")
    int updateOneReward(String userId);

    @Modifying
    @Transactional("writeTransactionManager")
    @Query("update RewardModel r set r.reward = r.reward+?2 where r.userId=?1")
    int updateReward(String userId, Integer v);

}
