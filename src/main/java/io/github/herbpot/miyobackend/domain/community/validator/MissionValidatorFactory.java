package io.github.herbpot.miyobackend.domain.community.validator;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * MissionValidatorFactory
 * - Strategy 패턴의 Factory 클래스
 * - 카테고리에 맞는 MissionValidator 반환
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MissionValidatorFactory {

    private final List<MissionValidator> validators;
    private Map<String, MissionValidator> validatorMap;

    /**
     * 카테고리에 해당하는 Validator 반환
     *
     * @param category "proposal", "empathy", "comment"
     * @return 해당 카테고리의 Validator
     * @throws IllegalArgumentException 해당 카테고리의 Validator가 없는 경우
     */
    public MissionValidator getValidator(String category) {
        if (validatorMap == null) {
            // Lazy initialization
            validatorMap = validators.stream()
                    .collect(Collectors.toMap(
                            MissionValidator::getCategory,
                            Function.identity()
                    ));
        }

        MissionValidator validator = validatorMap.get(category);
        if (validator == null) {
            log.warn("No validator found for category: {}", category);
            throw new IllegalArgumentException("지원하지 않는 미션 카테고리입니다: " + category);
        }

        return validator;
    }

    /**
     * 해당 카테고리의 Validator가 존재하는지 확인
     */
    public boolean hasValidator(String category) {
        if (validatorMap == null) {
            validatorMap = validators.stream()
                    .collect(Collectors.toMap(
                            MissionValidator::getCategory,
                            Function.identity()
                    ));
        }
        return validatorMap.containsKey(category);
    }
}
