-- MySQL 초기화 스크립트 (Read DB)
-- posts_read, empathy_data 테이블 생성
-- Read Service에서 사용

USE post_read_db;

-- Read Model 테이블
CREATE TABLE IF NOT EXISTS posts_read (
    post_id BIGINT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    user_nickname VARCHAR(50) NOT NULL,
    parent_post_id BIGINT,
    image_path VARCHAR(500),
    location POINT NOT NULL SRID 4326,
    category VARCHAR(20) NOT NULL,
    title VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    empathy_count INT DEFAULT 0,
    INDEX idx_user_id (user_id),
    INDEX idx_category (category),
    INDEX idx_created_at (created_at),
    INDEX idx_empathy_count (empathy_count),
    SPATIAL INDEX idx_location (location)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 공감 데이터 테이블
CREATE TABLE IF NOT EXISTS empathy_data (
    empathy_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    post_id BIGINT NOT NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_post_id (post_id),
    INDEX idx_user_id (user_id),
    UNIQUE KEY uk_user_post (user_id, post_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 초기화 완료 확인용 데이터
SELECT 'Read DB initialized successfully!' as message;
