package io.github.herbpot.miyobackend.domain.user.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Health Check", description = "서버 상태 확인 API")
@RestController
@RequestMapping("/")
public class MainController {

    @Operation(summary = "헬스 체크", description = "서버가 정상적으로 실행되고 있는지 확인합니다. K8s ingress health check에 사용됩니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "서버 정상 작동")
    })
    @GetMapping("/")
    public ResponseEntity<Void> index() {
        return ResponseEntity.ok().build();
    }
}
