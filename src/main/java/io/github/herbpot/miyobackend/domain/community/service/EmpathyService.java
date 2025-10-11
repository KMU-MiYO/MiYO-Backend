package io.github.herbpot.miyobackend.domain.community.service;

import io.github.herbpot.miyobackend.domain.community.entity.EmpathyData;
import io.github.herbpot.miyobackend.domain.community.repository.EmpathyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * EmpathyService
 * - 공감 추가/삭제 서비스
 * - 한 사용자가 한 게시글에 하나의 공감만 가능
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmpathyService {

    private final EmpathyRepository empathyRepository;

    /**
     * 공감 토글
     * - 공감이 없으면 추가, 있으면 삭제
     *
     * @param userId 사용자 ID
     * @param postId 게시글 ID
     * @return true: 공감 추가됨, false: 공감 삭제됨
     */
    @Transactional
    public boolean toggleEmpathy(Long userId, Long postId) {
        log.info("Toggling empathy: userId={}, postId={}", userId, postId);

        // 기존 공감 확인
        var existingEmpathy = empathyRepository.findByUserIdAndPostId(userId, postId);

        if (existingEmpathy.isPresent()) {
            // 공감이 있으면 삭제
            empathyRepository.delete(existingEmpathy.get());
            log.info("Empathy removed: empathyId={}", existingEmpathy.get().getEmpathyId());
            return false;
        } else {
            // 공감이 없으면 추가
            EmpathyData empathyData = EmpathyData.builder()
                    .userId(userId)
                    .postId(postId)
                    .build();

            empathyRepository.save(empathyData);
            log.info("Empathy added: empathyId={}", empathyData.getEmpathyId());
            return true;
        }
    }
}
