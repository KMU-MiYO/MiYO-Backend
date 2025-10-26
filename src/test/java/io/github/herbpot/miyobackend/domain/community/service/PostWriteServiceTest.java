package io.github.herbpot.miyobackend.domain.community.service;

import io.github.herbpot.miyobackend.client.UserServiceClient;
import io.github.herbpot.miyobackend.domain.community.dto.PostCreateRequest;
import io.github.herbpot.miyobackend.domain.community.dto.PostResponse;
import io.github.herbpot.miyobackend.domain.community.entity.Post;
import io.github.herbpot.miyobackend.domain.community.entity.PostCategory;
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

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * PostWriteService 단위 테스트
 * - Mockito를 사용하여 의존성 모킹
 * - 게시글 생성 및 삭제 기능 검증
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("PostWriteService 테스트")
class PostWriteServiceTest {

    @Mock
    private PostRepository postRepository;

    @Mock
    private RedisEventPublisher redisEventPublisher;

    @Mock
    private UserServiceClient userServiceClient;

    @InjectMocks
    private PostWriteService postWriteService;

    private static final GeometryFactory GEOMETRY_FACTORY = new GeometryFactory(new PrecisionModel(), 4326);

    private PostCreateRequest validRequest;
    private Post savedPost;
    private String testUserId;
    private String testUserNickname;

    @BeforeEach
    void setUp() {
        testUserId = "test-user-123";
        testUserNickname = "테스터";

        // 유효한 게시글 작성 요청 생성
        validRequest = new PostCreateRequest(
                null,  // parentPostId
                "https://example.com/image.jpg",  // imagePath
                37.5665,  // latitude (서울)
                126.9780,  // longitude (서울)
                PostCategory.COMMERCIAL,  // category
                "맛집 발견!",  // title
                "여기 진짜 맛있어요!"  // content
        );

        // 저장된 게시글 생성
        Point location = GEOMETRY_FACTORY.createPoint(new Coordinate(126.9780, 37.5665));
        savedPost = Post.builder()
                .userId(testUserId)
                .parentPostId(null)
                .imagePath("https://example.com/image.jpg")
                .location(location)
                .category(PostCategory.COMMERCIAL)
                .title("맛집 발견!")
                .content("여기 진짜 맛있어요!")
                .build();
    }

    @Test
    @DisplayName("게시글 생성 성공")
    void createPost_Success() {
        // Given
        when(userServiceClient.getUserNickname(testUserId)).thenReturn(testUserNickname);
        when(postRepository.save(any(Post.class))).thenReturn(savedPost);
        doNothing().when(redisEventPublisher).publish(any());

        // When
        PostResponse response = postWriteService.createPost(validRequest, testUserId);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getUserId()).isEqualTo(testUserId);
        assertThat(response.getUserNickname()).isEqualTo(testUserNickname);
        assertThat(response.getTitle()).isEqualTo("맛집 발견!");
        assertThat(response.getContent()).isEqualTo("여기 진짜 맛있어요!");
        assertThat(response.getCategory()).isEqualTo(PostCategory.COMMERCIAL);
        assertThat(response.getLatitude()).isEqualTo(37.5665);
        assertThat(response.getLongitude()).isEqualTo(126.9780);

        // Verify
        verify(userServiceClient, times(1)).getUserNickname(testUserId);
        verify(postRepository, times(1)).save(any(Post.class));
        verify(redisEventPublisher, times(1)).publish(any());
    }

    @Test
    @DisplayName("댓글 게시글 생성 성공 (parentPostId 존재)")
    void createPost_WithParentPostId_Success() {
        // Given
        PostCreateRequest commentRequest = new PostCreateRequest(
                1L,  // parentPostId
                null,  // imagePath (댓글은 이미지 없음)
                37.5665,
                126.9780,
                PostCategory.COMMERCIAL,
                "댓글 제목",
                "댓글 내용"
        );

        Point location = GEOMETRY_FACTORY.createPoint(new Coordinate(126.9780, 37.5665));
        Post savedComment = Post.builder()
                .userId(testUserId)
                .parentPostId(1L)
                .imagePath(null)
                .location(location)
                .category(PostCategory.COMMERCIAL)
                .title("댓글 제목")
                .content("댓글 내용")
                .build();

        when(userServiceClient.getUserNickname(testUserId)).thenReturn(testUserNickname);
        when(postRepository.save(any(Post.class))).thenReturn(savedComment);
        doNothing().when(redisEventPublisher).publish(any());

        // When
        PostResponse response = postWriteService.createPost(commentRequest, testUserId);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getParentPostId()).isEqualTo(1L);
        assertThat(response.getImagePath()).isNull();

        // Verify
        verify(postRepository, times(1)).save(any(Post.class));
    }

    @Test
    @DisplayName("게시글 삭제 성공")
    void deletePost_Success() {
        // Given
        Long postId = 1L;
        when(postRepository.findByPostIdAndUserId(postId, testUserId))
                .thenReturn(Optional.of(savedPost));
        doNothing().when(postRepository).delete(savedPost);
        doNothing().when(redisEventPublisher).publish(any());

        // When
        postWriteService.deletePost(postId, testUserId);

        // Then
        verify(postRepository, times(1)).findByPostIdAndUserId(postId, testUserId);
        verify(postRepository, times(1)).delete(savedPost);
        verify(redisEventPublisher, times(1)).publish(any());
    }

    @Test
    @DisplayName("게시글 삭제 실패 - 존재하지 않는 게시글")
    void deletePost_NotFound() {
        // Given
        Long postId = 999L;
        when(postRepository.findByPostIdAndUserId(postId, testUserId))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> postWriteService.deletePost(postId, testUserId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("게시글이 존재하지 않거나 삭제 권한이 없습니다");

        verify(postRepository, times(1)).findByPostIdAndUserId(postId, testUserId);
        verify(postRepository, never()).delete(any());
        verify(redisEventPublisher, never()).publish(any());
    }

    @Test
    @DisplayName("게시글 삭제 실패 - 권한 없음 (다른 사용자)")
    void deletePost_Unauthorized() {
        // Given
        Long postId = 1L;
        String otherUserId = "other-user-456";
        when(postRepository.findByPostIdAndUserId(postId, otherUserId))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> postWriteService.deletePost(postId, otherUserId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("게시글이 존재하지 않거나 삭제 권한이 없습니다");

        verify(postRepository, times(1)).findByPostIdAndUserId(postId, otherUserId);
        verify(postRepository, never()).delete(any());
    }
}
