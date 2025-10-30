package io.github.herbpot.miyobackend.domain.badge.service;

import io.github.herbpot.miyobackend.domain.badge.dto.response.UserBadgeListResponse;
import io.github.herbpot.miyobackend.domain.badge.dto.response.UserBadgeResponse;
import io.github.herbpot.miyobackend.domain.badge.entity.Badge;
import io.github.herbpot.miyobackend.domain.badge.entity.UserBadge;
import io.github.herbpot.miyobackend.domain.badge.repository.UserBadgeRepository;
import io.github.herbpot.miyobackend.domain.user.entity.User;
import io.github.herbpot.miyobackend.domain.user.repository.UserRepository;
import io.github.herbpot.miyobackend.global.exception.CustomException;
import io.github.herbpot.miyobackend.global.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserBadgeService {

    private final UserBadgeRepository userBadgeRepository;
    private final UserRepository userRepository;
    private final BadgeService badgeService;

    @Transactional
    public void assignBadgeToUser(String userId, Long badgeId) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        Badge badge = badgeService.findBadgeEntityById(badgeId);

        // 중복 체크
        if (userBadgeRepository.existsByUserAndBadge(user, badge)) {
            throw new CustomException(ErrorCode.BADGE_ALREADY_ASSIGNED);
        }

        UserBadge userBadge = UserBadge.of(user, badge);
        userBadgeRepository.save(userBadge);
    }

    public UserBadgeListResponse getUserBadges(String userId) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        List<UserBadge> userBadges = userBadgeRepository.findByUser(user);
        Long count = userBadgeRepository.countByUser(user);

        List<UserBadgeResponse> badgeResponses = userBadges.stream()
                .map(UserBadgeResponse::from)
                .collect(Collectors.toList());

        return UserBadgeListResponse.of(count, badgeResponses);
    }

    public UserBadgeListResponse getMyBadges() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userId = authentication.getName();

        return getUserBadges(userId);
    }

    @Transactional
    public void removeBadgeFromUser(String userId, Long badgeId) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        Badge badge = badgeService.findBadgeEntityById(badgeId);

        UserBadge userBadge = userBadgeRepository.findByUserAndBadge(user, badge)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_BADGE_NOT_FOUND));

        userBadgeRepository.delete(userBadge);
    }
}
