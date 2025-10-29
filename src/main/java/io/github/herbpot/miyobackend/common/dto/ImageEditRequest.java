package io.github.herbpot.miyobackend.common.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * ImageEditRequest
 * - 이미지 기반 이미지 생성 요청 DTO
 * - 기존 이미지 URL과 프롬프트를 받아 새로운 이미지 생성
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ImageEditRequest {

    /**
     * 기존 이미지 URL
     */
    @NotBlank(message = "이미지 URL은 필수입니다.")
    private String imageUrl;

    /**
     * 이미지 수정/생성 프롬프트
     */
    @NotBlank(message = "프롬프트는 필수입니다.")
    @Size(max = 1000, message = "프롬프트는 1000자를 초과할 수 없습니다.")
    private String prompt;

    /**
     * 이미지 생성 개수 (기본값: 1)
     */
    private Integer numberOfImages = 1;

    /**
     * 이미지 크기 (기본값: 1024x1024)
     */
    private String size = "1024x1024";
}
