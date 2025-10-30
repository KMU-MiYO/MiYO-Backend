package io.github.herbpot.miyobackend.domain.community.listener;

import io.github.herbpot.miyobackend.domain.community.event.MissionEvent;
import io.github.herbpot.miyobackend.domain.community.validator.MissionValidator;
import io.github.herbpot.miyobackend.domain.community.validator.MissionValidatorFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * MissionEventListener
 * - Spring ApplicationEvent를 구독하여 Mission 진행도 업데이트
 * - Posts 도메인의 MissionEvent를 수신
 * - Mission Validator 패턴을 사용하여 진행도 증가
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MissionEventListener {

    private final MissionValidatorFactory missionValidatorFactory;

    /**
     * MissionEvent 처리
     * - TransactionalEventListener로 트랜잭션 커밋 전에 실행
     * - 게시글 저장과 미션 업데이트가 같은 트랜잭션 내에서 처리
     *
     * @param event Mission 이벤트
     */
    @TransactionalEventListener(phase = TransactionPhase.BEFORE_COMMIT)
    public void handleMissionEvent(MissionEvent event) {
        log.info("Received MissionEvent: userId={}, relatedId={}, actionType={}",
                event.getUserId(), event.getRelatedId(), event.getActionType());

        try {
            // Mission Validator를 통한 진행도 업데이트
            String category = event.getCategoryString();

            if (!missionValidatorFactory.hasValidator(category)) {
                log.warn("No validator found for category: {}", category);
                return;
            }

            MissionValidator validator = missionValidatorFactory.getValidator(category);
            validator.validateAndUpdateProgress(event.getUserId(), event.getRelatedId());

            log.info("Mission progress updated successfully: userId={}, actionType={}",
                    event.getUserId(), event.getActionType());

        } catch (Exception e) {
            log.error("Failed to update mission progress: userId={}, actionType={}, error={}",
                    event.getUserId(), event.getActionType(), e.getMessage(), e);
            // 예외를 다시 던지면 전체 트랜잭션이 롤백됨
            // 미션 업데이트 실패가 게시글 작성에 영향을 주지 않으려면 예외를 삼킴
            // throw e; // 트랜잭션 롤백을 원하면 주석 해제
        }
    }
}
