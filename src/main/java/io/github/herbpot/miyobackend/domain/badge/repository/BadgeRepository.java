package io.github.herbpot.miyobackend.domain.badge.repository;

import io.github.herbpot.miyobackend.domain.badge.entity.Badge;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BadgeRepository extends JpaRepository<Badge, Long> {
}
