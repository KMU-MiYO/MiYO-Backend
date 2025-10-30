package io.github.herbpot.miyobackend.domain.challenge.dto;

import io.github.herbpot.miyobackend.domain.challenge.entity.ContestPost;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * ContestPostSummaryResponse
 * - 제출물 요약 정보 응답 DTO (리스트 조회용)
 * - title, userId, imagePath, empathy, createdAt만 포함
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContestPostSummaryResponse {

    /**
     * 제출물 ID
     */
    private Long id;

    /**
     * 제목
     */
    private String title;

    /**
     * 작성자 ID
     */
    private String userId;

    /**
     * 작성자 닉네임
     */
    private String userNickname;

    /**
     * 카테고리
     */
    private String category;

    /**
     * 이미지 경로
     */
    private String imagePath;

    /**
     * 공감 개수
     */
    private Integer empathy;

    /**
     * 작성 시각
     */
    private LocalDateTime createdAt;

    /**
     * ContestPost 엔티티로부터 ContestPostSummaryResponse 생성
     *
     * @param contestPost ContestPost 엔티티
     * @return ContestPostSummaryResponse
     */
    public static ContestPostSummaryResponse from(ContestPost contestPost) {
        return ContestPostSummaryResponse.builder()
                .id(contestPost.getId())
                .title(contestPost.getTitle())
                .userId(contestPost.getUserId())
                .imagePath(contestPost.getImagePath())
                .empathy(contestPost.getEmpathy())
                .createdAt(contestPost.getCreatedAt())
                .build();
    }

    /**
     * ContestPost 엔티티와 사용자 닉네임으로부터 ContestPostSummaryResponse 생성
     *
     * @param contestPost ContestPost 엔티티
     * @param userNickname 사용자 닉네임
     * @return ContestPostSummaryResponse
     */
    public static ContestPostSummaryResponse fromWithNickname(ContestPost contestPost, String userNickname) {
        return ContestPostSummaryResponse.builder()
                .id(contestPost.getId())
                .title(contestPost.getTitle())
                .userId(contestPost.getUserId())
                .userNickname(userNickname)
                .category(contestPost.getCategory())
                .imagePath(contestPost.getImagePath())
                .empathy(contestPost.getEmpathy())
                .createdAt(contestPost.getCreatedAt())
                .build();
    }
}
