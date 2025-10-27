# 챌린지 API 개발 명세서

## 📋 목차
1. [개요](#개요)
2. [데이터베이스 설계](#데이터베이스-설계)
3. [아키텍처 설계](#아키텍처-설계)
4. [구현 전략](#구현-전략)
5. [미션 검증 시스템](#미션-검증-시스템)
6. [핵심 비즈니스 로직](#핵심-비즈니스-로직)

---

## 개요

### 시스템 구성
- **Contest (공모전)**: "2026 우리 동네 공원 상상하기" 같은 프로젝트성 챌린지
- **Mission (미션)**: 사용자 활동을 주기적으로 추적하는 시스템 (예: "제안 5번 하기", "공감 3번 하기")

### 핵심 특징
- Contest와 Mission은 독립적으로 운영
- 모든 유저에게 공통 미션 부여
- **매주 일요일 00:00 미션 자동 새로고침**
- **Strategy Pattern 기반 미션 검증**: 새로운 미션 추가 시 코드 수정 최소화

---

## 데이터베이스 설계

### 🗄️ DB 정보
- **Database Name**: `challenge`
- **초기화 파일**: `init-db.sql`

### 📊 전체 테이블 구조

#### 1️⃣ Contest 관련 테이블

##### **ContestData** (공모전 메타데이터)
```sql
CREATE TABLE ContestData (
    contest_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL COMMENT '공모전 제목',
    host VARCHAR(100) COMMENT '주관 기관',
    description TEXT COMMENT '설명',
    start_date DATE NOT NULL COMMENT '시작일',
    end_date DATE NOT NULL COMMENT '종료일',
    reward_1st INT COMMENT '1등 포인트',
    reward_2nd INT COMMENT '2등 포인트',
    reward_3rd INT COMMENT '3등 포인트',
    reward_description TEXT COMMENT '보상 설명',
    thumbnail_url VARCHAR(255) COMMENT '썸네일 이미지'
);
```

##### **ContestUser** (공모전 참가자)
```sql
CREATE TABLE ContestUser (
    contest_id BIGINT NOT NULL,
    user_id VARCHAR(255) NOT NULL COMMENT '유저 ID',
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '참여 일시',
    PRIMARY KEY (contest_id, user_id),
    FOREIGN KEY (contest_id) REFERENCES ContestData(contest_id) ON DELETE CASCADE
);
```

##### **ContestPost** (공모전 제출물)
```sql
CREATE TABLE ContestPost (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    contest_id BIGINT NOT NULL,
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
    UNIQUE KEY unique_contest_user (contest_id, user_id) COMMENT '1인 1제출 보장'
);
```

---

#### 2️⃣ Mission 관련 테이블

##### **Mission** (미션 정의)
```sql
CREATE TABLE Mission (
    mission_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL COMMENT '미션 이름 (예: 제안 5번 하기)',
    description TEXT COMMENT '설명',
    goal_count INT NOT NULL COMMENT '목표 횟수 (예: 5)',
    category VARCHAR(50) NOT NULL COMMENT '미션 종류 (proposal, empathy, comment 등)',
    period_type ENUM('weekly', 'monthly') NOT NULL COMMENT '주간/월간 구분',
    start_date DATE NOT NULL COMMENT '미션 시작일',
    end_date DATE NOT NULL COMMENT '미션 종료일',
    reward_points INT DEFAULT 0 COMMENT '완료 시 지급 포인트',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '생성 시각',
    INDEX idx_category_period (category, start_date, end_date) COMMENT '활성 미션 조회용 인덱스'
);
```

##### **UserMissionProgress** (유저별 미션 진행 현황)
```sql
CREATE TABLE UserMissionProgress (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    mission_id BIGINT NOT NULL,
    user_id VARCHAR(255) NOT NULL COMMENT '유저 ID',
    current_count INT DEFAULT 0 COMMENT '현재 수행 횟수',
    completed BOOLEAN DEFAULT FALSE COMMENT '완료 여부',
    completed_at DATETIME COMMENT '완료 시각',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '마지막 갱신 시각',
    FOREIGN KEY (mission_id) REFERENCES Mission(mission_id) ON DELETE CASCADE,
    UNIQUE KEY unique_mission_user (mission_id, user_id)
);
```

---

### 🔗 ERD 관계도

```
┌─────────────────┐
│  ContestData    │
│  (공모전 정보)    │
└────────┬────────┘
         │ 1
         │
    ┌────┴────┐
    │         │
    │ N       │ N
┌───▼───────┐ │
│ContestUser│ │ (1:N)
│(참가자)    │ │
└───────────┘ │
              │
        ┌─────▼──────┐
        │ContestPost │
        │(제출물)     │
        └────────────┘

┌──────────────┐
│   Mission    │
│ (미션 정의)   │
└──────┬───────┘
       │ 1
       │
       │ N
┌──────▼──────────────┐
│UserMissionProgress  │
│(유저별 미션 진행 현황)│
└─────────────────────┘
```

**관계 요약:**
- **Contest 도메인**: 공모전 중심 (참가, 제출물)
- **Mission 도메인**: 사용자 활동 중심 (주간 목표 관리)
- 두 도메인은 **독립적으로 운영**

---

## 아키텍처 설계

### 🎯 설계 방향: **하이브리드 접근** (분리 + 재사용)

#### ✅ 채택한 방식
**ContestPost를 별도 테이블로 분리하되, 공통 로직은 서비스 계층에서 재사용**

#### 📊 방식 비교

| 구분 | 통합 방식 | 분리 방식 (채택) |
|------|-----------|-----------------|
| 구조 | Post 테이블에 type 컬럼 추가 | ContestPost 별도 테이블 |
| 장점 | 코드 중복 최소화 | 명확한 책임 분리, Contest 로직 독립 |
| 단점 | 테이블 비대화, NULL 값 증가 | 일부 코드 중복 |
| MSA 전환 | 어려움 | 용이함 |

---

## 구현 전략

### 🏗️ 서비스 계층 구조

```
📦 challenge-api
 ├── 📂 common (공통 서비스)
 │   ├── FileUploadService      # 이미지/파일 업로드
 │   ├── ValidationService       # 입력 검증
 │   └── NotificationService     # 알림
 │
 ├── 📂 contest (공모전 도메인)
 │   ├── ContestService
 │   ├── ContestPostService      # Contest 전용 비즈니스 로직
 │   └── ContestUserService
 │
 └── 📂 mission (미션 도메인)
     ├── MissionService          # 미션 관리 및 Factory 역할
     ├── UserMissionProgressService
     └── validator               # 미션 검증 전략 패턴
         ├── MissionValidator (인터페이스)
         ├── ProposalMissionValidator
         ├── EmpathyMissionValidator
         └── CommentMissionValidator
```

### 💻 코드 재사용 전략

```java
// 1️⃣ 공통 서비스 정의
@Service
public class FileUploadService {
    public String uploadImage(MultipartFile file) {
        // 이미지 업로드 로직
    }
}

@Service
public class PostServiceHelper {
    public void validateContent(String content) {
        // 컨텐츠 검증 로직
    }
}

// 2️⃣ ContestPost는 독립 구현하되 공통 서비스 주입
@Service
public class ContestPostService {
    private final FileUploadService fileUploadService;
    private final PostServiceHelper postHelper;
    private final MissionService missionService;
    
    public ContestPost createSubmission(Long contestId, ContestPostDto dto) {
        // Contest 전용 로직
        validateContestRules(contestId, dto.getUserId());
        checkDuplicateSubmission(contestId, dto.getUserId());
        
        // 공통 로직 재사용
        String imageUrl = fileUploadService.uploadImage(dto.getFile());
        postHelper.validateContent(dto.getContent());
        
        // 저장
        ContestPost post = contestPostRepository.save(dto.toEntity());
        
        // 미션 진행 상황 업데이트 (비동기 권장)
        missionService.updateMissionProgress(dto.getUserId(), "proposal", post);
        
        return post;
    }
    
    private void validateContestRules(Long contestId, String userId) {
        // 1인 1제출 체크
        // 제출 기간 체크
        // 참가 여부 체크
    }
}
```

### 🌐 API 엔드포인트 설계

```
📍 Contest API
POST   /api/contests                          # 공모전 생성
GET    /api/contests                          # 공모전 목록
GET    /api/contests/{id}                     # 공모전 상세
POST   /api/contests/{id}/join                # 공모전 참가
POST   /api/contests/{id}/submit              # 제출물 등록 ⭐
GET    /api/contests/{id}/submissions         # 제출물 목록
GET    /api/contests/{id}/submissions/{postId} # 제출물 상세
PUT    /api/contests/{id}/submissions/{postId} # 제출물 수정
DELETE /api/contests/{id}/submissions/{postId} # 제출물 삭제

📍 Mission API
GET    /api/missions                          # 현재 진행 중인 미션 목록
GET    /api/missions/my-progress              # 내 미션 진행 현황
GET    /api/missions/{id}                     # 미션 상세 정보
# 미션 카운트는 각 행동(제안, 공감 등) API에서 자동 증가
```

---

## 미션 검증 시스템

### 🎯 설계 원칙: Strategy Pattern

**문제점**: 미션 타입이 추가될 때마다 각 API 코드를 수정해야 함
```java
// ❌ 나쁜 예: 하드코딩
@PostMapping("/proposals")
public void createProposal(...) {
    // ...제안 생성...
    
    // 미션 카운트 증가 (하드코딩!)
    if (mission.getType().equals("proposal")) {
        missionService.increment(...);
    }
}
```

**해결책**: MissionValidator 인터페이스를 통한 전략 패턴 적용

---

### 1️⃣ MissionValidator 인터페이스

```java
/**
 * 미션 검증 전략 인터페이스
 * 새로운 미션 타입 추가 시 이 인터페이스를 구현하면 됨
 */
public interface MissionValidator {
    
    /**
     * 이 validator가 처리할 수 있는 미션 타입인지 확인
     * @param missionCategory 미션 카테고리 (proposal, empathy, comment 등)
     * @return 처리 가능 여부
     */
    boolean supports(String missionCategory);
    
    /**
     * 미션 수행 조건을 검증
     * @param userId 사용자 ID
     * @param context 검증에 필요한 컨텍스트 객체 (Post, Empathy, Comment 등)
     * @throws ValidationException 검증 실패 시
     */
    void validate(String userId, Object context);
    
    /**
     * 미션 타입 반환
     * @return 미션 카테고리 문자열
     */
    String getMissionType();
}
```

---

### 2️⃣ 각 미션별 구현체

#### ProposalMissionValidator (제안 미션)
```java
@Component
public class ProposalMissionValidator implements MissionValidator {
    
    @Override
    public boolean supports(String missionCategory) {
        return "proposal".equals(missionCategory);
    }
    
    @Override
    public void validate(String userId, Object context) {
        // context는 제안 게시글 정보
        if (!(context instanceof Post)) {
            throw new IllegalArgumentException("Invalid context type for proposal mission");
        }
        
        Post post = (Post) context;
        
        // 실제로 제안이 작성되었는지 검증
        if (post == null || !post.getUserId().equals(userId)) {
            throw new ValidationException("Invalid proposal submission");
        }
        
        // 추가 검증 로직 (예: 최소 글자 수 체크 등)
        if (post.getContent().length() < 10) {
            throw new ValidationException("Proposal content too short");
        }
    }
    
    @Override
    public String getMissionType() {
        return "proposal";
    }
}
```

#### EmpathyMissionValidator (공감 미션)
```java
@Component
public class EmpathyMissionValidator implements MissionValidator {
    
    @Override
    public boolean supports(String missionCategory) {
        return "empathy".equals(missionCategory);
    }
    
    @Override
    public void validate(String userId, Object context) {
        if (!(context instanceof Empathy)) {
            throw new IllegalArgumentException("Invalid context type for empathy mission");
        }
        
        Empathy empathy = (Empathy) context;
        
        // 공감 검증 로직
        if (!empathy.getUserId().equals(userId)) {
            throw new ValidationException("Invalid empathy action");
        }
    }
    
    @Override
    public String getMissionType() {
        return "empathy";
    }
}
```

#### CommentMissionValidator (댓글 미션 - 확장 예시)
```java
@Component
public class CommentMissionValidator implements MissionValidator {
    
    @Override
    public boolean supports(String missionCategory) {
        return "comment".equals(missionCategory);
    }
    
    @Override
    public void validate(String userId, Object context) {
        if (!(context instanceof Comment)) {
            throw new IllegalArgumentException("Invalid context type for comment mission");
        }
        
        Comment comment = (Comment) context;
        
        // 댓글 검증 로직
        if (!comment.getUserId().equals(userId)) {
            throw new ValidationException("Invalid comment submission");
        }
        
        if (comment.getContent().length() < 5) {
            throw new ValidationException("Comment too short");
        }
    }
    
    @Override
    public String getMissionType() {
        return "comment";
    }
}
```

---

### 3️⃣ MissionService (Factory 역할)

```java
@Service
@Slf4j
public class MissionService {
    
    private final Map<String, MissionValidator> validators;
    private final UserMissionProgressRepository progressRepository;
    private final MissionRepository missionRepository;
    
    /**
     * Spring이 모든 MissionValidator 구현체를 자동 주입
     * @param validatorList MissionValidator 구현체 리스트
     */
    public MissionService(List<MissionValidator> validatorList,
                          UserMissionProgressRepository progressRepository,
                          MissionRepository missionRepository) {
        this.validators = validatorList.stream()
            .collect(Collectors.toMap(
                MissionValidator::getMissionType,
                validator -> validator
            ));
        this.progressRepository = progressRepository;
        this.missionRepository = missionRepository;
        
        log.info("Registered mission validators: {}", validators.keySet());
    }
    
    /**
     * 미션 진행 상황 업데이트
     * @param userId 사용자 ID
     * @param missionType 미션 타입 (proposal, empathy, comment 등)
     * @param context 검증에 필요한 컨텍스트 객체
     */
    @Transactional
    public void updateMissionProgress(String userId, String missionType, Object context) {
        // 1. 해당 타입의 Validator 찾기
        MissionValidator validator = validators.get(missionType);
        if (validator == null) {
            log.warn("Unknown mission type: {}", missionType);
            return;
        }
        
        // 2. 검증 수행
        try {
            validator.validate(userId, context);
        } catch (Exception e) {
            log.error("Mission validation failed for user {} and type {}", userId, missionType, e);
            return;
        }
        
        // 3. 현재 진행 중인 미션 조회
        List<Mission> activeMissions = missionRepository.findActiveMissionsByCategory(
            missionType,
            LocalDate.now()
        );
        
        if (activeMissions.isEmpty()) {
            log.info("No active missions for type: {}", missionType);
            return;
        }
        
        // 4. 각 미션의 진행 상황 업데이트
        for (Mission mission : activeMissions) {
            UserMissionProgress progress = progressRepository
                .findByMissionIdAndUserId(mission.getMissionId(), userId)
                .orElseGet(() -> createNewProgress(mission, userId));
            
            // 이미 완료된 미션은 스킵
            if (progress.getCompleted()) {
                continue;
            }
            
            // 카운트 증가
            progress.incrementCount();
            
            // 목표 달성 체크
            if (progress.getCurrentCount() >= mission.getGoalCount()) {
                progress.setCompleted(true);
                progress.setCompletedAt(LocalDateTime.now());
                
                // 포인트 지급 등 보상 처리
                grantReward(userId, mission);
                
                log.info("Mission completed - User: {}, Mission: {}", userId, mission.getTitle());
            }
            
            progressRepository.save(progress);
        }
    }
    
    /**
     * 새로운 미션 진행 상황 생성
     */
    private UserMissionProgress createNewProgress(Mission mission, String userId) {
        return UserMissionProgress.builder()
            .missionId(mission.getMissionId())
            .userId(userId)
            .currentCount(0)
            .completed(false)
            .build();
    }
    
    /**
     * 미션 완료 보상 지급
     */
    private void grantReward(String userId, Mission mission) {
        if (mission.getRewardPoints() > 0) {
            // 포인트 지급 로직 (포인트 서비스 호출)
            log.info("Granted {} points to user {} for completing mission {}", 
                mission.getRewardPoints(), userId, mission.getTitle());
        }
    }
    
    /**
     * 사용자의 현재 미션 진행 현황 조회
     */
    @Transactional(readOnly = true)
    public List<MissionProgressDto> getMyProgress(String userId) {
        List<Mission> activeMissions = missionRepository.findActiveMissions(LocalDate.now());
        
        return activeMissions.stream()
            .map(mission -> {
                UserMissionProgress progress = progressRepository
                    .findByMissionIdAndUserId(mission.getMissionId(), userId)
                    .orElse(null);
                
                return MissionProgressDto.of(mission, progress);
            })
            .collect(Collectors.toList());
    }
}
```

---

### 4️⃣ 실제 API에서 사용

```java
// ✅ 제안 게시글 작성 API
@Service
public class PostService {
    
    private final MissionService missionService;
    private final PostRepository postRepository;
    
    @Transactional
    public Post createProposal(PostDto dto) {
        // 제안 생성
        Post post = postRepository.save(dto.toEntity());
        
        // 미션 진행 상황 자동 업데이트 (비동기 권장)
        missionService.updateMissionProgress(
            dto.getUserId(), 
            "proposal",  // 미션 타입만 전달
            post         // 검증에 필요한 컨텍스트
        );
        
        return post;
    }
}

// ✅ 공감 API
@Service
public class EmpathyService {
    
    private final MissionService missionService;
    private final EmpathyRepository empathyRepository;
    
    @Transactional
    public void addEmpathy(Long postId, String userId) {
        // 공감 추가
        Empathy empathy = empathyRepository.save(new Empathy(postId, userId));
        
        // 공감 미션 자동 업데이트
        missionService.updateMissionProgress(userId, "empathy", empathy);
    }
}

// ✅ 댓글 API (나중에 추가되어도 기존 코드 수정 불필요!)
@Service
public class CommentService {
    
    private final MissionService missionService;
    private final CommentRepository commentRepository;
    
    @Transactional
    public Comment createComment(CommentDto dto) {
        // 댓글 생성
        Comment comment = commentRepository.save(dto.toEntity());
        
        // 댓글 미션 자동 업데이트
        missionService.updateMissionProgress(dto.getUserId(), "comment", comment);
        
        return comment;
    }
}
```

---

### 5️⃣ 이벤트 기반 아키텍처 (선택사항 - 더 깔끔한 분리)

```java
// 이벤트 정의
@Getter
@AllArgsConstructor
public class ProposalCreatedEvent {
    private final String userId;
    private final Post post;
}

// 게시글 서비스 (미션 로직 완전 분리)
@Service
public class PostService {
    
    private final ApplicationEventPublisher eventPublisher;
    private final PostRepository postRepository;
    
    @Transactional
    public Post createProposal(PostDto dto) {
        Post post = postRepository.save(dto.toEntity());
        
        // 이벤트 발행 (미션 서비스와 완전 분리)
        eventPublisher.publishEvent(
            new ProposalCreatedEvent(dto.getUserId(), post)
        );
        
        return post;
    }
}

// 미션 이벤트 리스너
@Component
@Slf4j
public class MissionEventListener {
    
    private final MissionService missionService;
    
    @EventListener
    @Async
    public void handleProposalCreated(ProposalCreatedEvent event) {
        log.debug("Handling ProposalCreatedEvent for user: {}", event.getUserId());
        missionService.updateMissionProgress(
            event.getUserId(), 
            "proposal", 
            event.getPost()
        );
    }
    
    @EventListener
    @Async
    public void handleEmpathyAdded(EmpathyAddedEvent event) {
        log.debug("Handling EmpathyAddedEvent for user: {}", event.getUserId());
        missionService.updateMissionProgress(
            event.getUserId(), 
            "empathy", 
            event.getEmpathy()
        );
    }
}
```

---

### 🎨 미션 시스템의 장점

| 기존 설계 | Strategy Pattern 적용 |
|----------|----------------------|
| 미션 추가 시 각 API 코드 수정 필요 | 새 Validator만 추가하면 끝 ✅ |
| 하드코딩된 미션 타입 | 동적으로 Validator 선택 ✅ |
| 테스트 어려움 | 각 Validator 독립 테스트 가능 ✅ |
| 유지보수 어려움 | OCP(개방-폐쇄 원칙) 준수 ✅ |
| 미션 변경 시 서버 배포 필요 | DB만 수정하면 됨 ✅ |

---

## 핵심 비즈니스 로직

### 1️⃣ 미션 자동 새로고침 (매주 일요일 00:00)

```java
@Component
@Slf4j
public class MissionScheduler {
    
    private final MissionRepository missionRepository;
    private final UserMissionProgressRepository progressRepository;
    
    /**
     * 매주 일요일 00:00에 주간 미션 리셋
     */
    @Scheduled(cron = "0 0 0 * * SUN")
    @Transactional
    public void resetWeeklyMissions() {
        log.info("Starting weekly mission reset...");
        
        LocalDate today = LocalDate.now();
        LocalDate nextSunday = today.plusWeeks(1);
        
        // 1. 이전 주 미션 종료 처리
        List<Mission> expiredMissions = missionRepository
            .findMissionsByEndDate(today.minusDays(1));
        
        for (Mission mission : expiredMissions) {
            log.info("Expiring mission: {}", mission.getTitle());
            // 미완료 사용자에게 알림 등 처리 가능
        }
        
        // 2. 새로운 주간 미션 생성
        Mission proposalMission = Mission.builder()
            .title("제안 5번 하기")
            .description("이번 주에 제안을 5번 작성해보세요!")
            .category("proposal")
            .goalCount(5)
            .periodType("weekly")
            .startDate(today)
            .endDate(nextSunday.minusDays(1))
            .rewardPoints(100)
            .build();
        
        Mission empathyMission = Mission.builder()
            .title("공감 3번 하기")
            .description("다른 사람의 제안에 공감해보세요!")
            .category("empathy")
            .goalCount(3)
            .periodType("weekly")
            .startDate(today)
            .endDate(nextSunday.minusDays(1))
            .rewardPoints(50)
            .build();
        
        missionRepository.saveAll(Arrays.asList(proposalMission, empathyMission));
        
        log.info("Weekly mission reset completed");
    }
    
    /**
     * 매월 1일 00:00에 월간 미션 리셋
     */
    @Scheduled(cron = "0 0 0 1 * ?")
    @Transactional
    public void resetMonthlyMissions() {
        log.info("Starting monthly mission reset...");
        
        LocalDate today = LocalDate.now();
        LocalDate endOfMonth = today.withDayOfMonth(today.lengthOfMonth());
        
        // 월간 미션 생성 로직
        Mission monthlyMission = Mission.builder()
            .title("이번 달 활동 목표")
            .description("한 달 동안 제안 20번 작성하기")
            .category("proposal")
            .goalCount(20)
            .periodType("monthly")
            .startDate(today)
            .endDate(endOfMonth)
            .rewardPoints(500)
            .build();
        
        missionRepository.save(monthlyMission);
        
        log.info("Monthly mission reset completed");
    }
}
```

---

### 2️⃣ Contest 제출물 제약 조건

```java
@Service
public class ContestPostService {
    
    private final ContestPostRepository contestPostRepository;
    private final ContestUserRepository contestUserRepository;
    private final ContestRepository contestRepository;
    
    /**
     * 제출물 검증
     */
    public void validateSubmission(Long contestId, String userId) {
        // 1. 참가 여부 확인
        if (!contestUserRepository.existsByContestIdAndUserId(contestId, userId)) {
            throw new NotJoinedException("공모전에 참가하지 않은 사용자입니다.");
        }
        
        // 2. 1인 1제출 확인
        if (contestPostRepository.existsByContestIdAndUserId(contestId, userId)) {
            throw new DuplicateSubmissionException("이미 제출물을 등록했습니다.");
        }
        
        // 3. 제출 기간 확인
        ContestData contest = contestRepository.findById(contestId)
            .orElseThrow(() -> new ContestNotFoundException("공모전을 찾을 수 없습니다."));
        
        LocalDate today = LocalDate.now();
        if (today.isBefore(contest.getStartDate()) || today.isAfter(contest.getEndDate())) {
            throw new SubmissionClosedException("제출 기간이 아닙니다.");
        }
    }
    
    /**
     * 제출물 등록
     */
    @Transactional
    public ContestPost createSubmission(Long contestId, ContestPostDto dto) {
        // 검증
        validateSubmission(contestId, dto.getUserId());
        
        // 저장
        ContestPost post = ContestPost.builder()
            .contestId(contestId)
            .userId(dto.getUserId())
            .title(dto.getTitle())
            .content(dto.getContent())
            .category(dto.getCategory())
            .imagePath(dto.getImagePath())
            .build();
        
        return contestPostRepository.save(post);
    }
}
```

---

### 3️⃣ 미션 진행 현황 조회

```java
@RestController
@RequestMapping("/api/missions")
public class MissionController {
    
    private final MissionService missionService;
    
    /**
     * 현재 진행 중인 미션 목록 조회
     */
    @GetMapping
    public ResponseEntity<List<MissionDto>> getActiveMissions() {
        List<Mission> missions = missionService.getActiveMissions();
        return ResponseEntity.ok(
            missions.stream()
                .map(MissionDto::from)
                .collect(Collectors.toList())
        );
    }
    
    /**
     * 내 미션 진행 현황 조회
     */
    @GetMapping("/my-progress")
    public ResponseEntity<List<MissionProgressDto>> getMyProgress(
        @AuthenticationPrincipal UserDetails userDetails
    ) {
        String userId = userDetails.getUsername();
        List<MissionProgressDto> progress = missionService.getMyProgress(userId);
        return ResponseEntity.ok(progress);
    }
}

/**
 * 미션 진행 현황 DTO
 */
@Getter
@Builder
public class MissionProgressDto {
    private Long missionId;
    private String title;
    private String description;
    private String category;
    private int goalCount;
    private int currentCount;
    private boolean completed;
    private int rewardPoints;
    private LocalDate endDate;
    
    public static MissionProgressDto of(Mission mission, UserMissionProgress progress) {
        return MissionProgressDto.builder()
            .missionId(mission.getMissionId())
            .title(mission.getTitle())
            .description(mission.getDescription())
            .category(mission.getCategory())
            .goalCount(mission.getGoalCount())
            .currentCount(progress != null ? progress.getCurrentCount() : 0)
            .completed(progress != null && progress.getCompleted())
            .rewardPoints(mission.getRewardPoints())
            .endDate(mission.getEndDate())
            .build();
    }
}
```

---

## 📝 구현 체크리스트

### Phase 1: 데이터베이스 구축
- [ ] MySQL 서버 생성 (DB명: `challenge`)
- [ ] `init-db.sql` 작성 및 실행
- [ ] 테이블 생성 확인

### Phase 2: Entity 및 Repository
- [ ] Contest 관련 Entity 작성
    - [ ] ContestData
    - [ ] ContestUser
    - [ ] ContestPost
- [ ] Mission 관련 Entity 작성
    - [ ] Mission
    - [ ] UserMissionProgress
- [ ] Repository 인터페이스 작성

### Phase 3: 미션 검증 시스템
- [ ] MissionValidator 인터페이스 정의
- [ ] ProposalMissionValidator 구현
- [ ] EmpathyMissionValidator 구현
- [ ] MissionService (Factory) 구현
- [ ] 단위 테스트 작성

### Phase 4: Contest 서비스
- [ ] 공통 서비스 구현
    - [ ] FileUploadService
    - [ ] ValidationService
- [ ] ContestService 구현
- [ ] ContestPostService 구현
- [ ] ContestUserService 구현

### Phase 5: Mission 서비스
- [ ] MissionService 구현
- [ ] UserMissionProgressService 구현
- [ ] MissionScheduler 구현 (주간 리셋)

### Phase 6: API Controller
- [ ] ContestController 구현
- [ ] MissionController 구현
- [ ] DTO 작성
- [ ] 예외 처리

### Phase 7: 테스트 및 최적화
- [ ] 통합 테스트 작성
- [ ] 성능 테스트
- [ ] API 문서화 (Swagger)

---

