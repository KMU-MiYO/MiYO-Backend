package io.github.herbpot.miyobackend.domain.community.service;

import io.github.herbpot.miyobackend.domain.community.dto.EmpathyEvent;
import io.github.herbpot.miyobackend.domain.community.entity.write.EmpathyData;
import io.github.herbpot.miyobackend.domain.community.repository.write.EmpathyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * EmpathyService
 * - 공감 추가/삭제 서비스
 * - 한 사용자가 한 게시글에 하나의 공감만 가능
 * - Write DB에 저장 후 Redis 이벤트 발행
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmpathyService {

    private final EmpathyRepository empathyRepository;
    private final RedisEventPublisher redisEventPublisher;

    /**
     * 공감 토글
     * - 공감이 없으면 추가, 있으면 삭제
     * - Write DB에 저장 후 Redis 이벤트 발행
     *
     * @param userId 사용자 ID
     * @param postId 게시글 ID
     * @return true: 공감 추가됨, false: 공감 삭제됨
     */
    @Transactional("writeTransactionManager")
    public boolean toggleEmpathy(String userId, Long postId) {
        log.info("Toggling empathy: userId={}, postId={}", userId, postId);

        // 기존 공감 확인 (Write DB)
        var existingEmpathy = empathyRepository.findByUserIdAndPostId(userId, postId);

        if (existingEmpathy.isPresent()) {
            // 공감이 있으면 삭제
            EmpathyData empathyData = existingEmpathy.get();
            empathyRepository.delete(empathyData);
            log.info("Empathy removed from write DB: empathyId={}", empathyData.getEmpathyId());

            // Redis 이벤트 발행 (DELETE)
            EmpathyEvent event = EmpathyEvent.deleteEvent(empathyData);
            redisEventPublisher.publishEmpathyEvent(event);

            return false;
        } else {
            // 공감이 없으면 추가
            EmpathyData empathyData = EmpathyData.builder()
                    .userId(userId)
                    .postId(postId)
                    .build();

            EmpathyData savedEmpathy = empathyRepository.save(empathyData);
            log.info("Empathy added to write DB: empathyId={}", savedEmpathy.getEmpathyId());

            // Redis 이벤트 발행 (CREATE)
            EmpathyEvent event = EmpathyEvent.createEvent(savedEmpathy);
            redisEventPublisher.publishEmpathyEvent(event);

            return true;
        }
    }
}
