package io.github.herbpot.miyobackend.domain.community.dto;

/**
 * Event
 * - Redis Pub/Sub을 통해 전달되는 이벤트의 공통 인터페이스
 * - PostEvent, EmpathyEvent 등이 이 인터페이스를 구현
 */
public interface Event {
    /**
     * 이벤트 타입을 문자열로 반환
     * - 이벤트 구분을 위한 타입 정보
     */
    String getEventTypeName();
}
