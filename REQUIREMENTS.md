/**
* 공모전 제출물 상세 조회
*
* @param contestId 공모전 ID (현재는 검증용)
* @param postId 제출물 ID
* @return 제출물 상세 정보 (200 OK)
*/
@Operation(
summary = "공모전 제출물 상세 조회",
description = """
특정 공모전 제출물의 상세 정보를 조회합니다.

                    - 제출물의 모든 정보 반환
                    - 댓글은 별도 API로 조회
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = ContestPostResponse.class))
            ),
            @ApiResponse(responseCode = "404", description = "제출물을 찾을 수 없음")
    })
    @GetMapping("/{contestId}/posts/{postId}")
    public ResponseEntity<ContestPostResponse> getPostById(
            @Parameter(description = "공모전 ID", required = true)
            @PathVariable Long contestId,
            @Parameter(description = "제출물 ID", required = true)
            @PathVariable Long postId,
            @Parameter(hidden = true) @RequestHeader("Authorization") String token) {

        log.info("GET /v0/contests/{}/posts/{} - Getting post details", contestId, postId);

        ContestPostResponse post = contestPostService.getPostById(postId, token);
        return ResponseEntity.ok(post);
    }

    /**
     * 제출물에 댓글 작성
     *
     * @param postId 부모 제출물 ID
     * @param request 댓글 작성 요청
     * @param authentication Spring Security Authentication
     * @return 생성된 댓글 정보 (201 Created)
     */
    @Operation(
            summary = "제출물에 댓글 작성",
            description = """
                    특정 제출물에 댓글을 작성합니다.

                    - 텍스트 댓글 작성
                    - JWT 인증 필요
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "댓글 작성 성공",
                    content = @Content(schema = @Schema(implementation = ContestPostResponse.class))
            ),
            @ApiResponse(responseCode = "404", description = "제출물을 찾을 수 없음"),
            @ApiResponse(responseCode = "400", description = "잘못된 요청 데이터"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @PostMapping("/posts/{postId}/comments")
    public ResponseEntity<ContestPostResponse> createComment(
            @Parameter(description = "제출물 ID", required = true)
            @PathVariable Long postId,
            @Valid @RequestBody ContestPostCommentRequest request,
            @Parameter(hidden = true) Authentication authentication,
            @Parameter(hidden = true) @RequestHeader("Authorization") String token) {

        String userId = (String) authentication.getPrincipal();
        log.info("POST /v0/contests/posts/{}/comments - Creating comment: userId={}", postId, userId);

        ContestPostResponse response = contestPostService.createComment(postId, request, userId, token);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 제출물의 댓글 목록 조회
     *
     * @param postId 부모 제출물 ID
     * @param pageable 페이징 정보
     * @return 댓글 목록 (200 OK)
     */
    @Operation(
            summary = "제출물의 댓글 목록 조회",
            description = """
                    특정 제출물의 댓글 목록을 조회합니다.

                    - 시간순 정렬 (오래된 순)
                    - 페이징 지원 (기본 20개)
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = ContestPostResponse.class))
            ),
            @ApiResponse(responseCode = "404", description = "제출물을 찾을 수 없음")
    })
    @GetMapping("/posts/{postId}/comments")
    public ResponseEntity<Page<ContestPostResponse>> getCommentsByPostId(
            @Parameter(description = "제출물 ID", required = true)
            @PathVariable Long postId,
            @Parameter(description = "페이징 정보 (기본 20개, 시간순 정렬)")
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.ASC) Pageable pageable,
            @Parameter(hidden = true) @RequestHeader("Authorization") String token) {

        log.info("GET /v0/contests/posts/{}/comments - Getting comments: page={}", postId, pageable.getPageNumber());

        Page<ContestPostResponse> comments = contestPostService.getCommentsByPostId(postId, pageable, token);
        return ResponseEntity.ok(comments);
    }