package io.github.herbpot.miyobackend.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT Authentication Filter
 * - Authorization 헤더에서 JWT 토큰 추출
 * - JWT 토큰 검증 및 userId 추출
 * - Spring Security Context에 인증 정보 저장
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        String method = request.getMethod();

        log.info("JWT Filter - Processing request: {} {}", method, requestURI);

        // permitAll 경로는 JWT 검증 없이 통과 (선택적 인증)
        boolean isPublicEndpoint = requestURI.startsWith("/actuator/")
                || requestURI.startsWith("/dev/posts/swagger-ui/")
                || requestURI.startsWith("/dev/posts/v3/api-docs/")
                || requestURI.equals("/dev/posts/swagger-ui.html")
                || requestURI.equals("/v0/posts/cord")
                || requestURI.equals("/v0/posts/id")
                || requestURI.equals("/v0/posts/top3")
                || requestURI.equals("/");

        if (isPublicEndpoint) {
            log.debug("JWT Filter - Public endpoint, attempting optional authentication: {}", requestURI);
        }

        // Authorization 헤더에서 JWT 토큰 추출
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null) {
            if (!isPublicEndpoint) {
                log.warn("JWT Filter - No Authorization header found for: {} {}", method, requestURI);
            }
        } else if (!authHeader.startsWith("Bearer ")) {
            log.warn("JWT Filter - Authorization header does not start with 'Bearer ': {}", authHeader.substring(0, Math.min(20, authHeader.length())));
        } else {
            String token = authHeader.substring(7); // "Bearer " 제거
            log.info("JWT Filter - Token extracted, length: {}", token.length());

            try {
                // JWT 토큰 검증
                if (jwtUtil.validateToken(token)) {
                    // JWT에서 userId 추출
                    String userId = jwtUtil.getUserIdFromToken(token);

                    log.info("JWT Filter - Token validated successfully: userId={}", userId);

                    // Spring Security Authentication 객체 생성
                    // principal에 userId를 저장
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userId, // principal: userId
                                    null,   // credentials: 비밀번호 불필요
                                    List.of(new SimpleGrantedAuthority("ROLE_USER")) // authorities
                            );

                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Spring Security Context에 인증 정보 저장
                    SecurityContextHolder.getContext().setAuthentication(authentication);

                    log.info("JWT Filter - Authentication set in SecurityContext for userId: {}", userId);
                } else {
                    log.warn("JWT Filter - Token validation failed for: {} {}", method, requestURI);
                }
            } catch (Exception e) {
                log.error("JWT Filter - JWT authentication failed for: {} {}", method, requestURI, e);
            }
        }

        // 다음 필터로 진행
        filterChain.doFilter(request, response);
    }
}
