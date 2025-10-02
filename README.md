## contest-90-backend
> Creator: contest90
> Date: 2025/09/24

## Description 
* contest-90-backend에 대한 설명을 작성하세요

# 핵심 기능
## user-curd

- 사용자 관리 (로그인, 가입, 탈퇴, 정보 수정), 사용자 증명 및 조회를 위한 기능 개발
- JWT를 사용하여 사용자 검증할 것 (단 토큰 내부에는 최소 정보만 관리하고 필요 시 5번 기능을 통해 조회하도록 해야 함)
- 사용자 정보는 아래를 포함해야 함
    1. 닉네임
    2. 아이디 (unique)
    3. 이메일
    4. 비밀번호
    5. 가입일자
    6. 프로필 사진
    7. 뱃지 리스트
    8. 좋아요 표시한 게시글 리스트
    9. 댓글 리스트
    10. 게시글 리스트
- 사용자 정보에 포함되는 각 리스트는 다대다 구조를 가지며 별도의 테이블로 관리되어야 함

### ✅ 체크리스트

- [x] Assignees / Labels / Milestone 선택 (N/A - Project Management Task)
- [x]  로그인 (io.github.herbpot.miyobackend.domain.user.controller.UserRestController, io.github.herbpot.miyobackend.domain.user.service.UserService, io.github.herbpot.miyobackend.config.SecurityConfig, io.github.herbpot.miyobackend.global.jwt.JwtAuthenticationFilter, io.github.herbpot.miyobackend.global.jwt.JwtUtil)
- [x]  로그아웃 (io.github.herbpot.miyobackend.domain.user.controller.UserRestController)
- [x]  회원 가입 (io.github.herbpot.miyobackend.domain.user.controller.UserRestController, io.github.herbpot.miyobackend.domain.user.service.UserService)
    - [x] 이메일 인증코드 요청 (io.github.herbpot.miyobackend.domain.user.controller.UserRestController, io.github.herbpot.miyobackend.domain.user.service.UserService, io.github.herbpot.miyobackend.global.mail.EmailService)
- [x]  사용자 검증 (io.github.herbpot.miyobackend.global.jwt.JwtAuthenticationFilter, io.github.herbpot.miyobackend.global.jwt.JwtUtil, io.github.herbpot.miyobackend.config.SecurityConfig, io.github.herbpot.miyobackend.domain.user.service.CustomUserDetailsService)
- [x]  사용자 정보 조회 (io.github.herbpot.miyobackend.domain.user.controller.UserRestController, io.github.herbpot.miyobackend.domain.user.service.UserService)
- [x]  계정 삭제 (io.github.herbpot.miyobackend.domain.user.controller.UserRestController, io.github.herbpot.miyobackend.domain.user.service.UserService)
- [x]  회원정보 수정 (io.github.herbpot.miyobackend.domain.user.controller.UserRestController, io.github.herbpot.miyobackend.domain.user.service.UserService)
- [x]  아이디 찾기 / 비밀번호 재설정 (io.github.herbpot.miyobackend.domain.user.controller.UserRestController, io.github.herbpot.miyobackend.domain.user.service.UserService, io.github.herbpot.miyobackend.domain.user.repository.UserRepository, io.github.herbpot.miyobackend.global.mail.EmailService)