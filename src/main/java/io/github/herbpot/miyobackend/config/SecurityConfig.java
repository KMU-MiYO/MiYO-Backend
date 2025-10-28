package io.github.herbpot.miyobackend.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security Configuration
 * - JWT 기반 인증 설정
 * - Stateless 세션 정책 (세션 사용 안 함)
 * - CSRF 비활성화 (JWT 사용으로 불필요)
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF 비활성화 (JWT 사용으로 불필요)
                .csrf(AbstractHttpConfigurer::disable)

                // 세션 사용 안 함 (Stateless)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // 인증/인가 설정
                .authorizeHttpRequests(auth -> auth
                        // 헬스체크, 액추에이터는 인증 없이 접근 가능
                        .requestMatchers("/actuator/**").permitAll()

                        // Swagger UI 및 OpenAPI 문서는 인증 없이 접근 가능
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/swagger-ui.html").permitAll()

                        // 게시글 조회 API는 인증 선택 (인증 없이도 가능, 있으면 공감 여부 확인)
                        .requestMatchers("/v0/posts/cord", "/v0/posts/id", "/v0/posts/top3").permitAll()

                        // 공모전 목록/상세 조회는 인증 불필요
                        .requestMatchers("/v0/contests", "/v0/contests/*").permitAll()

                        // 관리자 API는 인증 불필요 (URL 비공개로 보안)
                        .requestMatchers("/v0/contests/adminMiYO/**").permitAll()

                        // 이미지 헬스체크는 인증 불필요
                        .requestMatchers("/v0/images/health").permitAll()

                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // 나머지 API는 인증 필요
                        .anyRequest().authenticated()
                )

                // JWT 필터 추가 (UsernamePasswordAuthenticationFilter 이전에 실행)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
