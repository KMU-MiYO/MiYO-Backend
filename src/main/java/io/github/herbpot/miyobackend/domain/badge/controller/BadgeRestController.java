package io.github.herbpot.miyobackend.domain.badge.controller;

import io.github.herbpot.miyobackend.domain.badge.dto.request.CreateBadgeRequest;
import io.github.herbpot.miyobackend.domain.badge.dto.request.UpdateBadgeRequest;
import io.github.herbpot.miyobackend.domain.badge.dto.response.BadgeResponse;
import io.github.herbpot.miyobackend.domain.badge.service.BadgeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "Badge", description = "뱃지 관리 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/badges")
public class BadgeRestController {

    private final BadgeService badgeService;

    @Operation(
            summary = "뱃지 생성",
            description = "새로운 뱃지를 생성합니다. 뱃지 이름, 설명, 이미지를 포함해야 합니다. JWT 인증이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "뱃지 생성 성공",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = BadgeResponse.class)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청", content = @Content),
            @ApiResponse(responseCode = "401", description = "인증 실패", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<BadgeResponse> createBadge(@ModelAttribute CreateBadgeRequest request) {
        BadgeResponse response = badgeService.createBadge(request);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "전체 뱃지 목록 조회",
            description = "시스템에 등록된 모든 뱃지 목록을 조회합니다. JWT 인증이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = BadgeResponse.class)
                    )
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @GetMapping
    public ResponseEntity<List<BadgeResponse>> getAllBadges() {
        List<BadgeResponse> badges = badgeService.getAllBadges();
        return ResponseEntity.ok(badges);
    }

    @Operation(
            summary = "특정 뱃지 조회",
            description = "뱃지 ID로 특정 뱃지의 상세 정보를 조회합니다. JWT 인증이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = BadgeResponse.class)
                    )
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패", content = @Content),
            @ApiResponse(responseCode = "404", description = "뱃지를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @GetMapping("/{badgeId}")
    public ResponseEntity<BadgeResponse> getBadgeById(
            @Parameter(description = "뱃지 ID", example = "1")
            @PathVariable Long badgeId
    ) {
        BadgeResponse response = badgeService.getBadgeById(badgeId);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "뱃지 정보 수정",
            description = "기존 뱃지의 정보를 수정합니다. 이름, 설명, 이미지를 변경할 수 있습니다. JWT 인증이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "수정 성공",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = BadgeResponse.class)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청", content = @Content),
            @ApiResponse(responseCode = "401", description = "인증 실패", content = @Content),
            @ApiResponse(responseCode = "404", description = "뱃지를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @PatchMapping(value = "/{badgeId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<BadgeResponse> updateBadge(
            @Parameter(description = "뱃지 ID", example = "1")
            @PathVariable Long badgeId,
            @ModelAttribute UpdateBadgeRequest request
    ) {
        BadgeResponse response = badgeService.updateBadge(badgeId, request);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "뱃지 삭제",
            description = "특정 뱃지를 삭제합니다. 뱃지 이미지도 함께 삭제됩니다. JWT 인증이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "삭제 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패", content = @Content),
            @ApiResponse(responseCode = "404", description = "뱃지를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @DeleteMapping("/{badgeId}")
    public ResponseEntity<Void> deleteBadge(
            @Parameter(description = "뱃지 ID", example = "1")
            @PathVariable Long badgeId
    ) {
        badgeService.deleteBadge(badgeId);
        return ResponseEntity.ok().build();
    }
}
