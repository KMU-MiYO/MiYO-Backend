package io.github.herbpot.miyobackend.domain.community.entity.read;

import io.github.herbpot.miyobackend.domain.community.entity.PostCategory;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.locationtech.jts.geom.Point;

import java.time.LocalDateTime;

/**
 * PostReadModel Entity (Read Model)
 * - CQRS 패턴에서 읽기 모델로 사용
 * - posts_read 테이블에 매핑
 * - Write Model(Post)의 데이터를 Redis Pub/Sub을 통해 비동기로 복제
 * - 조회 성능 최적화를 위한 인덱스 설정
 * - MySQL Spatial Index를 활용한 위치 기반 검색
 */
@Entity
@Table(name = "posts_read", indexes = {
    @Index(name = "idx_user_id", columnList = "user_id"),
    @Index(name = "idx_category", columnList = "category"),
    @Index(name = "idx_created_at", columnList = "created_at"),
    @Index(name = "idx_empathy_count", columnList = "empathy_count")
    // Spatial Index는 @Index로 생성 불가, DDL로 별도 생성 필요:
    // CREATE SPATIAL INDEX idx_location ON posts_read(location);
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PostReadModel {

    /**
     * 게시글 ID (Primary Key)
     * - Write Model의 postId와 동일한 값 사용 (동기화)
     */
    @Id
    @Column(name = "post_id")
    private Long postId;

    /**
     * 작성자 ID
     * - User 테이블의 id 참조 (Foreign Key)
     */
    @Column(name = "user_id", nullable = false)
    private String userId;

    /**
     * 작성자 닉네임
     * - 조회 성능 최적화를 위한 비정규화 필드
     * - User Service에서 가져온 닉네임 저장
     */
    @Column(name = "user_nickname", nullable = false, length = 50)
    private String userNickname;

    /**
     * 부모 게시글 ID
     * - null이면 원본 게시글, 값이 있으면 답글/댓글
     */
    @Column(name = "parent_post_id")
    private Long parentPostId;

    /**
     * 이미지 경로 (URL)
     */
    @Column(name = "image_path", length = 500)
    private String imagePath;

    /**
     * 위치 정보 (MySQL POINT 타입)
     * - SRID 4326: WGS84 좌표계 (GPS 좌표)
     * - Spatial Index를 통해 빠른 반경 검색 지원
     * - ST_Distance_Sphere 함수와 함께 사용
     */
    @Column(name = "location", columnDefinition = "POINT SRID 4326", nullable = false)
    private Point location;

    /**
     * 게시글 카테고리
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "category", nullable = false, length = 20)
    private PostCategory category;

    /**
     * 게시글 제목
     */
    @Column(name = "title", nullable = false, length = 100)
    private String title;

    /**
     * 게시글 내용
     * - TEXT 타입으로 긴 텍스트 저장 가능
     */
    @Column(name = "content", columnDefinition = "TEXT", nullable = false)
    private String content;

    /**
     * 생성 일시
     * - Write Model의 createdAt과 동일한 값 저장
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * 공감 수
     * - 조회 성능 최적화를 위한 비정규화 필드
     */
    @Column(name = "empathy_count")
    private Integer empathyCount;

    /**
     * Builder 패턴을 사용한 생성자
     * - Redis 이벤트 구독 시 PostEvent로부터 데이터를 받아 생성
     */
    @Builder
    public PostReadModel(Long postId, String userId, String userNickname, Long parentPostId,
                         String imagePath, Point location, PostCategory category,
                         String title, String content, LocalDateTime createdAt,
                         Integer empathyCount) {
        this.postId = postId;
        this.userId = userId;
        this.userNickname = userNickname;
        this.parentPostId = parentPostId;
        this.imagePath = imagePath;
        this.location = location;
        this.category = category;
        this.title = title;
        this.content = content;
        this.createdAt = createdAt;
        this.empathyCount = empathyCount != null ? empathyCount : 0;
    }

    /**
     * 위도(latitude) 반환
     * - Point 객체에서 Y 좌표 추출
     */
    public double getLatitude() {
        return location.getY();
    }

    /**
     * 경도(longitude) 반환
     * - Point 객체에서 X 좌표 추출
     */
    public double getLongitude() {
        return location.getX();
    }
}
