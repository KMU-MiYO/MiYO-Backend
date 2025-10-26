package io.github.herbpot.miyobackend.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * JWT Utility Class
 * - JWT 토큰 파싱 및 검증
 * - user-service에서 발급한 JWT에서 userId 추출
 * - HMAC 대칭키 방식 사용 (Base64 디코딩)
 */
@Slf4j
@Component
public class JwtUtil {

    private final SecretKey secretKey;

    public JwtUtil(@Value("${jwt.decode-key}") String decodeKey) {
        // JWT Decode Key (Base64 디코딩 후 HMAC 키 생성)
        // user-service와 동일한 방식
        try {
            byte[] keyBytes = java.util.Base64.getDecoder().decode(decodeKey);
            this.secretKey = Keys.hmacShaKeyFor(keyBytes);
            log.info("JWT Decode Key loaded successfully (Base64 decoded, key length: {} bytes)", keyBytes.length);
        } catch (Exception e) {
            log.error("Failed to decode JWT key: {}", e.getMessage());
            log.error("Key value (first 20 chars): {}", decodeKey.substring(0, Math.min(20, decodeKey.length())));
            throw new IllegalArgumentException("Invalid JWT decode key format. Must be valid Base64 encoded string.", e);
        }
    }

    /**
     * JWT에서 userId 추출
     * @param token JWT 토큰
     * @return userId (String)
     */
    public String getUserIdFromToken(String token) {
        try {
            Claims claims = parseClaims(token);
            // userId는 subject에 저장되어 있다고 가정
            return claims.getSubject();
        } catch (Exception e) {
            log.error("Failed to extract userId from token", e);
            throw new IllegalArgumentException("Invalid JWT token", e);
        }
    }

    /**
     * JWT 토큰 검증
     * @param token JWT 토큰
     * @return 유효하면 true, 아니면 false
     */
    public boolean validateToken(String token) {
        try {
            Claims claims = parseClaims(token);
            Date expiration = claims.getExpiration();
            boolean isExpired = expiration.before(new Date());

            if (isExpired) {
                log.warn("JWT token expired. Expiration: {}, Current: {}", expiration, new Date());
                return false;
            }

            log.info("JWT token validation successful. Subject: {}, Expiration: {}", claims.getSubject(), expiration);
            return true;
        } catch (io.jsonwebtoken.security.SignatureException e) {
            log.error("JWT token validation failed - Invalid signature: {}", e.getMessage());
            log.error("This usually means the decode key in posts-service doesn't match the encode key used by user-service");
            return false;
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            log.warn("JWT token validation failed - Token expired: {}", e.getMessage());
            return false;
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            log.error("JWT token validation failed - Malformed token: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("JWT token validation failed - Unexpected error: {}", e.getClass().getSimpleName(), e);
            return false;
        }
    }

    /**
     * JWT 토큰 파싱
     * @param token JWT 토큰
     * @return Claims
     */
    private Claims parseClaims(String token) {
        try {
            log.debug("Parsing JWT token...");
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            log.debug("JWT token parsed successfully. Subject: {}", claims.getSubject());
            return claims;
        } catch (Exception e) {
            log.error("Failed to parse JWT token: {}", e.getMessage());
            throw e;
        }
    }
}
