-- Challenge Database Initialization
-- Database: content_db (기존 데이터베이스 사용)
-- Challenge 관련 테이블들을 content_db에 추가

USE content_db;

-- 공모전 메타데이터 테이블
CREATE TABLE IF NOT EXISTS ContestData (
    contest_id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '공모전 ID',
    title VARCHAR(255) NOT NULL COMMENT '공모전 제목',
    host VARCHAR(100) COMMENT '주관 기관',
    description TEXT COMMENT '설명',
    start_date DATE NOT NULL COMMENT '시작일',
    end_date DATE NOT NULL COMMENT '종료일',
    reward_1st INT COMMENT '1등 포인트',
    reward_2nd INT COMMENT '2등 포인트',
    reward_3rd INT COMMENT '3등 포인트',
    reward_description TEXT COMMENT '보상 설명',
    thumbnail_url VARCHAR(255) COMMENT '썸네일 이미지',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '생성 시각',
    INDEX idx_dates (start_date, end_date) COMMENT '기간 조회용 인덱스'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='공모전 메타데이터';

-- 공모전 참가자 테이블
CREATE TABLE IF NOT EXISTS ContestUser (
    contest_id BIGINT NOT NULL COMMENT '공모전 ID',
    user_id VARCHAR(255) NOT NULL COMMENT '유저 ID',
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '참여 일시',
    PRIMARY KEY (contest_id, user_id),
    FOREIGN KEY (contest_id) REFERENCES ContestData(contest_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id) COMMENT '유저별 참가 목록 조회용'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='공모전 참가자';

-- 공모전 제출물 테이블
CREATE TABLE IF NOT EXISTS ContestPost (
    id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '제출물 ID',
    contest_id BIGINT NOT NULL COMMENT '공모전 ID',
    parent_post_id BIGINT COMMENT '부모 게시글 ID (댓글용)',
    user_id VARCHAR(255) NOT NULL COMMENT '작성자 ID',
    title VARCHAR(100) COMMENT '제안 제목',
    content TEXT NOT NULL COMMENT '제출 내용',
    category VARCHAR(20) COMMENT '카테고리',
    image_path VARCHAR(500) COMMENT '이미지 경로',
    file_url VARCHAR(255) COMMENT '첨부 파일 경로',
    empathy INT DEFAULT 0 COMMENT '공감 개수',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '작성 시각',
    FOREIGN KEY (contest_id) REFERENCES ContestData(contest_id) ON DELETE CASCADE,
    UNIQUE KEY unique_contest_user (contest_id, user_id) COMMENT '1인 1제출 보장',
    INDEX idx_contest_id (contest_id) COMMENT '공모전별 제출물 조회용'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='공모전 제출물';

-- 미션 정의 테이블
CREATE TABLE IF NOT EXISTS Mission (
    mission_id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '미션 ID',
    title VARCHAR(255) NOT NULL COMMENT '미션 이름',
    description TEXT COMMENT '설명',
    goal_count INT NOT NULL COMMENT '목표 횟수',
    category VARCHAR(50) NOT NULL COMMENT '미션 종류 (proposal, empathy, comment 등)',
    period_type ENUM('weekly', 'monthly') NOT NULL COMMENT '주간/월간 구분',
    start_date DATE NOT NULL COMMENT '미션 시작일',
    end_date DATE NOT NULL COMMENT '미션 종료일',
    reward_points INT DEFAULT 0 COMMENT '완료 시 지급 포인트',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '생성 시각',
    INDEX idx_category_period (category, start_date, end_date) COMMENT '활성 미션 조회용 인덱스',
    INDEX idx_dates (start_date, end_date) COMMENT '기간별 조회용'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='미션 정의';

-- 유저별 미션 진행 현황 테이블
CREATE TABLE IF NOT EXISTS UserMissionProgress (
    id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '진행 상황 ID',
    mission_id BIGINT NOT NULL COMMENT '미션 ID',
    user_id VARCHAR(255) NOT NULL COMMENT '유저 ID',
    current_count INT DEFAULT 0 COMMENT '현재 수행 횟수',
    completed BOOLEAN DEFAULT FALSE COMMENT '완료 여부',
    completed_at DATETIME COMMENT '완료 시각',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '마지막 갱신 시각',
    FOREIGN KEY (mission_id) REFERENCES Mission(mission_id) ON DELETE CASCADE,
    UNIQUE KEY unique_mission_user (mission_id, user_id) COMMENT '미션-유저 조합 유일성',
    INDEX idx_user_id (user_id) COMMENT '유저별 진행 현황 조회용'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='유저별 미션 진행 현황';
