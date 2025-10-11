package io.github.herbpot.miyobackend.domain.community.dto;

import org.springframework.data.domain.Page;

import java.util.List;

/**
 * PageResponse
 * - 페이징 응답 DTO
 * - Spring Data Page를 프론트엔드 친화적인 형태로 변환
 * - 불필요한 메타데이터 제거
 */
public record PageResponse<T>(
        List<T> content,
        int page,
        int size,
        long totalElements,
        int totalPages
) {
    /**
     * Spring Data Page를 PageResponse로 변환
     */
    public static <T> PageResponse<T> from(Page<T> page) {
        return new PageResponse<>(
                page.getContent(),
                page.getNumber(),
                page.getSize(),
                page.getTotalElements(),
                page.getTotalPages()
        );
    }
}
