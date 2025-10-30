package io.github.herbpot.miyobackend.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Swagger/OpenAPI Configuration
 * - Springdoc OpenAPI를 사용한 API 문서화
 * - JWT Bearer Token 인증 지원
 * - 접속 URL: http://localhost:8080/swagger-ui.html
 */
@Configuration
public class SwaggerConfig {

    @Value("${server.port:8080}")
    private String serverPort;

    @Bean
    public OpenAPI openAPI() {
        String jwtSchemeName = "JWT";

        // JWT 인증 요구사항 설정
        SecurityRequirement securityRequirement = new SecurityRequirement()
                .addList(jwtSchemeName);

        // JWT Security Scheme 설정
        SecurityScheme securityScheme = new SecurityScheme()
                .name(jwtSchemeName)
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .in(SecurityScheme.In.HEADER)
                .description("JWT 토큰을 입력하세요. 예: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");

        Components components = new Components()
                .addSecuritySchemes(jwtSchemeName, securityScheme);

        return new OpenAPI()
                .info(apiInfo())
                .addSecurityItem(securityRequirement)
                .components(components);
    }

    /**
     * API 기본 정보 설정
     */
    private Info apiInfo() {
        return new Info()
                .title("MiYO Backend Challenge API")
                .description("""
                        # MiYO 프로젝트 백엔드 Challenge API

                        ## 개요
                        - MiYO 프로젝트의 공모전, 미션, 이미지 생성 관련 API를 제공합니다.
                        - JWT 기반 인증을 사용합니다.

                        ## 인증 방법
                        1. JWT 토큰을 발급받습니다.
                        2. 우측 상단의 'Authorize' 버튼을 클릭합니다.
                        3. 발급받은 JWT 토큰을 입력합니다. (Bearer 접두사는 자동으로 추가됩니다)

                        ## API 구조
                        - `/v0/contests`: 공모전 관련 API
                        - `/v0/missions`: 미션 관련 API
                        - `/v0/images`: AI 이미지 생성 API
                        - `/v0/adminMiYO`: 관리자 전용 API

                        ## 주요 기능
                        - 공모전 조회, 참가, 제출물 작성
                        - 미션 조회 및 진행도 관리
                        - AI 이미지 생성 및 업로드
                        - 관리자 공모전/미션 관리
                        """)
                .version("v0.0.1")
                .license(new License()
                        .name("Apache 2.0")
                        .url("https://www.apache.org/licenses/LICENSE-2.0.html"));
    }
}
