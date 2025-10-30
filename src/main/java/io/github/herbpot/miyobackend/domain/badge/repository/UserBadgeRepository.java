package io.github.herbpot.miyobackend.domain.badge.repository;

import io.github.herbpot.miyobackend.domain.badge.entity.Badge;
import io.github.herbpot.miyobackend.domain.badge.entity.UserBadge;
import io.github.herbpot.miyobackend.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserBadgeRepository extends JpaRepository<UserBadge, Long> {

    List<UserBadge> findByUser(User user);

    Optional<UserBadge> findByUserAndBadge(User user, Badge badge);

    boolean existsByUserAndBadge(User user, Badge badge);

    Long countByUser(User user);
}
