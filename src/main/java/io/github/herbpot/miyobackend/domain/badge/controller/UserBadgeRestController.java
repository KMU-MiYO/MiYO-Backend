package io.github.herbpot.miyobackend.domain.badge.controller;

import io.github.herbpot.miyobackend.domain.badge.dto.request.AssignBadgeRequest;
import io.github.herbpot.miyobackend.domain.badge.dto.response.UserBadgeListResponse;
import io.github.herbpot.miyobackend.domain.badge.service.UserBadgeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Tag(name = "User Badge", description = "사용자 뱃지 관리 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/users/bedge")
public class UserBadgeRestController {

    private final UserBadgeService userBadgeService;

    @Operation(
            summary = "사용자에게 뱃지 부여",
            description = "특정 사용자에게 뱃지를 부여합니다. JWT 인증이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "뱃지 부여 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패", content = @Content),
            @ApiResponse(responseCode = "404", description = "사용자 또는 뱃지를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "409", description = "이미 보유한 뱃지", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @PostMapping("/{userId}/badges")
    public ResponseEntity<Void> assignBadgeToUser(
            @Parameter(description = "사용자 ID", example = "hong123")
            @PathVariable String userId,
            @RequestBody AssignBadgeRequest request
    ) {
        userBadgeService.assignBadgeToUser(userId, request.getBadgeId());
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "사용자의 뱃지 목록 조회",
            description = "특정 사용자가 보유한 뱃지 목록과 개수를 조회합니다. JWT 인증이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserBadgeListResponse.class)
                    )
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패", content = @Content),
            @ApiResponse(responseCode = "404", description = "사용자를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @GetMapping("/{userId}/badges")
    public ResponseEntity<UserBadgeListResponse> getUserBadges(
            @Parameter(description = "사용자 ID", example = "hong123")
            @PathVariable String userId
    ) {
        UserBadgeListResponse response = userBadgeService.getUserBadges(userId);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "내 뱃지 목록 조회",
            description = "현재 로그인한 사용자의 뱃지 목록과 개수를 조회합니다. JWT 인증이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserBadgeListResponse.class)
                    )
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패", content = @Content),
            @ApiResponse(responseCode = "404", description = "사용자를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @GetMapping("/my/badges")
    public ResponseEntity<UserBadgeListResponse> getMyBadges() {
        UserBadgeListResponse response = userBadgeService.getMyBadges();
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "사용자의 뱃지 제거",
            description = "특정 사용자로부터 뱃지를 제거합니다. JWT 인증이 필요합니다.",
            security = @SecurityRequirement(name = "JWT")
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "뱃지 제거 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패", content = @Content),
            @ApiResponse(responseCode = "404", description = "사용자, 뱃지 또는 사용자 뱃지를 찾을 수 없음", content = @Content),
            @ApiResponse(responseCode = "500", description = "서버 오류", content = @Content)
    })
    @DeleteMapping("/{userId}/badges/{badgeId}")
    public ResponseEntity<Void> removeBadgeFromUser(
            @Parameter(description = "사용자 ID", example = "hong123")
            @PathVariable String userId,
            @Parameter(description = "뱃지 ID", example = "1")
            @PathVariable Long badgeId
    ) {
        userBadgeService.removeBadgeFromUser(userId, badgeId);
        return ResponseEntity.ok().build();
    }
}
