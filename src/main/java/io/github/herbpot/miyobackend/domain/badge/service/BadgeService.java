package io.github.herbpot.miyobackend.domain.badge.service;

import io.github.herbpot.miyobackend.domain.badge.dto.request.CreateBadgeRequest;
import io.github.herbpot.miyobackend.domain.badge.dto.request.UpdateBadgeRequest;
import io.github.herbpot.miyobackend.domain.badge.dto.response.BadgeResponse;
import io.github.herbpot.miyobackend.domain.badge.entity.Badge;
import io.github.herbpot.miyobackend.domain.badge.repository.BadgeRepository;
import io.github.herbpot.miyobackend.domain.user.service.ObjectStorageService;
import io.github.herbpot.miyobackend.global.exception.CustomException;
import io.github.herbpot.miyobackend.global.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class BadgeService {

    private final BadgeRepository badgeRepository;
    private final ObjectStorageService objectStorageService;

    @Transactional
    public BadgeResponse createBadge(CreateBadgeRequest request) {
        // 뱃지 이미지 업로드
        String imageUrl = objectStorageService.uploadBadgeImage(request.getBadgeImage());

        // 뱃지 생성
        Badge badge = Badge.of(
                request.getName(),
                request.getDescription(),
                imageUrl
        );

        Badge savedBadge = badgeRepository.save(badge);
        return BadgeResponse.from(savedBadge);
    }

    public List<BadgeResponse> getAllBadges() {
        return badgeRepository.findAll().stream()
                .map(BadgeResponse::from)
                .collect(Collectors.toList());
    }

    public BadgeResponse getBadgeById(Long badgeId) {
        Badge badge = badgeRepository.findById(badgeId)
                .orElseThrow(() -> new CustomException(ErrorCode.BADGE_NOT_FOUND));
        return BadgeResponse.from(badge);
    }

    @Transactional
    public BadgeResponse updateBadge(Long badgeId, UpdateBadgeRequest request) {
        Badge badge = badgeRepository.findById(badgeId)
                .orElseThrow(() -> new CustomException(ErrorCode.BADGE_NOT_FOUND));

        // 새 이미지가 제공된 경우
        String newImageUrl = null;
        if (request.getBadgeImage() != null && !request.getBadgeImage().isEmpty()) {
            // 기존 이미지 삭제
            if (badge.getImageUrl() != null) {
                objectStorageService.removeBadgeImage(badge.getImageUrl());
            }
            // 새 이미지 업로드
            newImageUrl = objectStorageService.uploadBadgeImage(request.getBadgeImage());
        }

        // 뱃지 정보 업데이트
        badge.update(request.getName(), request.getDescription(), newImageUrl);

        return BadgeResponse.from(badge);
    }

    @Transactional
    public void deleteBadge(Long badgeId) {
        Badge badge = badgeRepository.findById(badgeId)
                .orElseThrow(() -> new CustomException(ErrorCode.BADGE_NOT_FOUND));

        // 이미지 삭제
        if (badge.getImageUrl() != null) {
            objectStorageService.removeBadgeImage(badge.getImageUrl());
        }

        badgeRepository.delete(badge);
    }

    public Badge findBadgeEntityById(Long badgeId) {
        return badgeRepository.findById(badgeId)
                .orElseThrow(() -> new CustomException(ErrorCode.BADGE_NOT_FOUND));
    }
}
