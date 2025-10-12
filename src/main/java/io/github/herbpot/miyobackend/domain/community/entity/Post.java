package io.github.herbpot.miyobackend.domain.community.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.locationtech.jts.geom.Point;

import java.time.LocalDateTime;

/**
 * Post Entity (Write Model)
 * - CQRS 패턴에서 쓰기 모델로 사용
 * - posts_write 테이블에 매핑
 * - MySQL Spatial Point 타입을 사용하여 위치 정보 저장 (SRID 4326: WGS84 좌표계)
 */
@Entity
@Table(name = "posts_write", indexes = {
    @Index(name = "idx_user_id", columnList = "user_id"),
    @Index(name = "idx_created_at", columnList = "created_at")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Post {

    /**
     * 게시글 ID (Primary Key)
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "post_id")
    private Long postId;

    /**
     * 작성자 ID
     * - User 테이블의 id 참조 (Foreign Key)
     */
    @Column(name = "user_id", nullable = false)
    private String userId;

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
     * - columnDefinition: MySQL의 POINT 타입으로 명시적 지정
     * - JTS(Java Topology Suite) Point 객체 사용
     */
    @Column(name = "location", columnDefinition = "POINT SRID 4326", nullable = false)
    private Point location;

    /**
     * 게시글 카테고리
     * - Enum 타입, DB에는 문자열로 저장
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
     * - 자동으로 현재 시각 설정
     */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Builder 패턴을 사용한 생성자
     * - 불변 객체 생성 지향
     * - location은 GeometryFactory를 통해 생성된 Point 객체를 받음
     */
    @Builder
    public Post(String userId, Long parentPostId, String imagePath,
                Point location, PostCategory category, String title, String content) {
        this.userId = userId;
        this.parentPostId = parentPostId;
        this.imagePath = imagePath;
        this.location = location;
        this.category = category;
        this.title = title;
        this.content = content;
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
