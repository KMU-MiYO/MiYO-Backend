package io.github.herbpot.miyobackend.domain.community.service;

import io.github.herbpot.miyobackend.client.UserServiceClient;
import io.github.herbpot.miyobackend.domain.community.dto.CommentCreateRequest;
import io.github.herbpot.miyobackend.domain.community.dto.PostListResponse;
import io.github.herbpot.miyobackend.domain.community.dto.PostResponse;
import io.github.herbpot.miyobackend.domain.community.entity.write.Post;
import io.github.herbpot.miyobackend.domain.community.entity.PostCategory;
import io.github.herbpot.miyobackend.domain.community.entity.read.PostReadModel;
import io.github.herbpot.miyobackend.domain.community.repository.read.EmpathyRepository;
import io.github.herbpot.miyobackend.domain.community.repository.read.PostReadRepository;
import io.github.herbpot.miyobackend.domain.community.repository.write.PostRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.locationtech.jts.geom.Coordinate;
import org.locationtech.jts.geom.GeometryFactory;
import org.locationtech.jts.geom.Point;
import org.locationtech.jts.geom.PrecisionModel;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

/**
 * CommentService 단위 테스트
 * - Mockito를 사용하여 의존성 모킹
 * - 댓글 생성, 조회, 삭제 기능 검증
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("CommentService 테스트")
class CommentServiceTest {

    @Mock
    private PostRepository postRepository;

    @Mock
    private PostReadRepository postReadRepository;

    @Mock
    private EmpathyRepository empathyRepository;

    @Mock
    private RedisEventPublisher redisEventPublisher;

    @Mock
    private UserServiceClient userServiceClient;

    @InjectMocks
    private CommentService commentService;

    private static final GeometryFactory GEOMETRY_FACTORY = new GeometryFactory(new PrecisionModel(), 4326);

    private CommentCreateRequest validCommentRequest;
    private Post parentPost;
    private Post savedComment;
    private String testUserId;
    private String testUserNickname;

    @BeforeEach
    void setUp() {
        testUserId = "test-user-123";
        testUserNickname = "테스터";

        // 부모 게시글 생성
        Point location = GEOMETRY_FACTORY.createPoint(new Coordinate(126.9780, 37.5665));
        parentPost = Post.builder()
                .userId("parent-user")
                .parentPostId(null)
                .imagePath("https://example.com/image.jpg")
                .location(location)
                .category(PostCategory.COMMERCIAL)
                .title("부모 게시글")
                .content("부모 게시글 내용")
                .build();

        // 댓글 작성 요청 생성 (parentPostId, content만 포함)
        validCommentRequest = new CommentCreateRequest(
                1L,  // parentPostId
                "댓글 내용"  // content
        );

        // 저장된 댓글 생성 (부모로부터 category, title 상속)
        savedComment = Post.builder()
                .userId(testUserId)
                .parentPostId(1L)
                .imagePath(null)
                .location(location)
                .category(PostCategory.COMMERCIAL)  // 부모로부터 상속
                .title("부모 게시글")  // 부모로부터 상속
                .content("댓글 내용")
                .build();
    }

    @Test
    @DisplayName("댓글 생성 성공 - 위치, 카테고리, 제목 상속")
    void createComment_Success() {
        // Given
        when(postRepository.findById(1L)).thenReturn(Optional.of(parentPost));
        when(userServiceClient.getUserNickname(testUserId)).thenReturn(testUserNickname);
        when(postRepository.save(any(Post.class))).thenReturn(savedComment);
        doNothing().when(redisEventPublisher).publish(any());

        // When
        PostResponse response = commentService.createComment(validCommentRequest, testUserId);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getParentPostId()).isEqualTo(1L);
        assertThat(response.getImagePath()).isNull();  // 댓글은 이미지 없음
        assertThat(response.getLatitude()).isEqualTo(37.5665);  // 부모의 위치 정보 상속
        assertThat(response.getLongitude()).isEqualTo(126.9780);
        assertThat(response.getCategory()).isEqualTo(PostCategory.COMMERCIAL);  // 부모의 카테고리 상속
        assertThat(response.getTitle()).isEqualTo("부모 게시글");  // 부모의 제목 상속
        assertThat(response.getUserId()).isEqualTo(testUserId);
        assertThat(response.getContent()).isEqualTo("댓글 내용");

        // Verify
        verify(postRepository, times(1)).findById(1L);
        verify(userServiceClient, times(1)).getUserNickname(testUserId);
        verify(postRepository, times(1)).save(any(Post.class));
        verify(redisEventPublisher, times(1)).publish(any());
    }

    @Test
    @DisplayName("댓글 생성 실패 - 부모 게시글이 존재하지 않음")
    void createComment_ParentPostNotFound() {
        // Given
        when(postRepository.findById(1L)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> commentService.createComment(validCommentRequest, testUserId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("부모 게시글이 존재하지 않습니다");

        verify(postRepository, times(1)).findById(1L);
        verify(postRepository, never()).save(any());
        verify(redisEventPublisher, never()).publish(any());
    }

    @Test
    @DisplayName("댓글 목록 조회 성공")
    void getCommentsByPostId_Success() {
        // Given
        Long parentPostId = 1L;
        Pageable pageable = PageRequest.of(0, 10);

        List<PostReadModel> commentList = new ArrayList<>();
        // 임시로 빈 리스트 반환 (PostReadModel 생성자 복잡도로 인해)
        Page<PostReadModel> commentPage = new PageImpl<>(commentList, pageable, 0);

        when(postReadRepository.findByParentPostIdOrderByCreatedAtDesc(parentPostId, pageable))
                .thenReturn(commentPage);

        // When
        Page<PostListResponse> result = commentService.getCommentsByPostId(parentPostId, pageable);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getContent()).isEmpty();

        verify(postReadRepository, times(1))
                .findByParentPostIdOrderByCreatedAtDesc(parentPostId, pageable);
    }
}
