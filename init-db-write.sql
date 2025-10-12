-- MySQL 초기화 스크립트 (Write DB)
-- posts_write 테이블 생성
-- Write Service에서 사용

USE posts_write_db;

-- Write Model 테이블
CREATE TABLE IF NOT EXISTS posts_write (
    post_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    parent_post_id BIGINT,
    image_path VARCHAR(500),
    location POINT NOT NULL SRID 4326,
    category VARCHAR(20) NOT NULL,
    title VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 초기화 완료 확인용 데이터
SELECT 'Write DB initialized successfully!' as message;
