package io.github.herbpot.miyobackend.domain.challenge.controller;


import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "헬스체크", description = "서버 상태 확인 API")
@RestController
@RequestMapping("/")
public class HealthcheckController {

    @Operation(
            summary = "서버 헬스체크",
            description = "서버가 정상적으로 동작하는지 확인합니다. 인증이 필요하지 않습니다."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "서버 정상 동작")
    })
    @GetMapping("/")
    public ResponseEntity<Void> index() {
        return ResponseEntity.ok().build();
    }
}