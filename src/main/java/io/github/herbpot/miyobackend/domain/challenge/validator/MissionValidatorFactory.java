package io.github.herbpot.miyobackend.domain.challenge.validator;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MissionValidatorFactory
 * - Factory Pattern을 사용한 검증자 관리
 * - 미션 카테고리에 따라 적절한 검증자를 반환
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MissionValidatorFactory {

    private final List<MissionValidator> validators;
    private final Map<String, MissionValidator> validatorMap = new HashMap<>();

    /**
     * 초기화 메서드
     * - 모든 검증자를 카테고리별로 맵에 등록
     */
    @PostConstruct
    public void init() {
        for (MissionValidator validator : validators) {
            validatorMap.put(validator.getCategory(), validator);
            log.info("Registered MissionValidator: category={}, validator={}",
                    validator.getCategory(), validator.getClass().getSimpleName());
        }
    }

    /**
     * 카테고리에 해당하는 검증자 반환
     *
     * @param category 미션 카테고리
     * @return 검증자 (없으면 null)
     */
    public MissionValidator getValidator(String category) {
        MissionValidator validator = validatorMap.get(category);
        if (validator == null) {
            log.warn("No validator found for category: {}", category);
        }
        return validator;
    }

    /**
     * 특정 카테고리의 검증자가 존재하는지 확인
     *
     * @param category 미션 카테고리
     * @return 존재 여부
     */
    public boolean hasValidator(String category) {
        return validatorMap.containsKey(category);
    }
}
