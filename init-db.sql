-- MySQL 초기화 스크립트
-- Docker Compose 실행 시 자동으로 실행됨

USE content_db;

-- User 테이블
CREATE TABLE IF NOT EXISTS user (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    nickname VARCHAR(100) NOT NULL,
    user_id VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    profile_picture VARCHAR(500),
    created_at DATETIME NOT NULL,
    password_reset_token VARCHAR(255),
    password_reset_token_expiry_date DATETIME,
    authority VARCHAR(50),
    INDEX idx_user_id (user_id),
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Write Model 테이블
CREATE TABLE IF NOT EXISTS posts_write (
    post_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    parent_post_id BIGINT,
    image_path VARCHAR(500),
    location POINT NOT NULL SRID 4326,
    category VARCHAR(20) NOT NULL,
    title VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Read Model 테이블
CREATE TABLE IF NOT EXISTS posts_read (
    post_id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    parent_post_id BIGINT,
    image_path VARCHAR(500),
    location POINT NOT NULL SRID 4326,
    category VARCHAR(20) NOT NULL,
    title VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    empathy_count INT DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_category (category),
    INDEX idx_created_at (created_at),
    INDEX idx_empathy_count (empathy_count),
    SPATIAL INDEX idx_location (location)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 공감 데이터 테이블
CREATE TABLE IF NOT EXISTS empathy_data (
    empathy_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    post_id BIGINT NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts_read(post_id) ON DELETE CASCADE,
    INDEX idx_post_id (post_id),
    INDEX idx_user_id (user_id),
    UNIQUE KEY uk_user_post (user_id, post_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 초기화 완료 확인용 데이터
SELECT 'Database initialized successfully!' as message;

--INSERT INTO user (id, nickname, user_id, email, password, profile_picture, created_at, authority) VALUES
--  (1, '테스트유저1', 'testuser1', 'test1@example.com', '$2a$10$dummyHashedPassword1', NULL, NOW(), 'ROLE_USER'),
--  (2, '테스트유저2', 'testuser2', 'test2@example.com', '$2a$10$dummyHashedPassword2', NULL, NOW(), 'ROLE_USER'),
--  (3, '홍길동', 'hong123', 'hong@example.com', '$2a$10$dummyHashedPassword3', NULL, NOW(), 'ROLE_USER'),
--  (4, '김철수', 'kim456', 'kim@example.com', '$2a$10$dummyHashedPassword4', NULL, NOW(), 'ROLE_USER'),
--  (5, '이영희', 'lee789', 'lee@example.com', '$2a$10$dummyHashedPassword5', 'https://example.com/profile5.jpg', NOW(), 'ROLE_USER');