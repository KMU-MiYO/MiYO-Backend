package io.github.herbpot.miyobackend.domain.community.dto;

import io.github.herbpot.miyobackend.domain.community.entity.read.PostReadModel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 댓글 응답 DTO
 * - 게시글 상세 조회 시 댓글 정보를 담는 DTO
 * - 제외 항목: 위치 정보, 제목, 이미지, 카테고리
 * - 대댓글 지원 (최대 2단계: 댓글 -> 대댓글)
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CommentResponse {

    /**
     * 댓글 ID
     */
    private Long postId;

    /**
     * 작성자 ID
     */
    private String userId;

    /**
     * 작성자 닉네임
     */
    private String userNickname;

    /**
     * 부모 게시글/댓글 ID
     * - 원본 게시글의 댓글이면 게시글 ID
     * - 대댓글이면 부모 댓글 ID
     */
    private Long parentPostId;

    /**
     * 댓글 내용
     */
    private String content;

    /**
     * 생성 일시
     */
    private LocalDateTime createdAt;

    /**
     * 공감 수
     */
    private Long empathyCount;

    /**
     * 사용자가 이 댓글에 공감했는지 여부
     * - 로그인하지 않은 경우 false
     */
    private Boolean isEmpathized;

    /**
     * 대댓글 목록
     * - 이 댓글의 자식 댓글들
     * - 최대 2단계까지만 (댓글의 대댓글은 replies가 항상 빈 배열)
     */
    private List<CommentResponse> replies;

    /**
     * PostReadModel로부터 CommentResponse 생성
     * - 위치 정보, 제목, 이미지, 카테고리 제외
     * - 대댓글은 별도로 설정
     */
    public static CommentResponse from(PostReadModel readModel, Long empathyCount, Boolean isEmpathized) {
        return CommentResponse.builder()
                .postId(readModel.getPostId())
                .userId(readModel.getUserId())
                .userNickname(readModel.getUserNickname())
                .parentPostId(readModel.getParentPostId())
                .content(readModel.getContent())
                .createdAt(readModel.getCreatedAt())
                .empathyCount(empathyCount != null ? empathyCount : 0L)
                .isEmpathized(isEmpathized != null ? isEmpathized : false)
                .replies(List.of())  // 초기에는 빈 리스트
                .build();
    }

    /**
     * 대댓글 설정
     */
    public void setReplies(List<CommentResponse> replies) {
        this.replies = replies;
    }
}
