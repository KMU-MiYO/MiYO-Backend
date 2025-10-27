# Challenge API 사용 가이드

## 📋 목차
1. [개요](#개요)
2. [API 엔드포인트](#api-엔드포인트)
3. [Contest API](#contest-api)
4. [Mission API](#mission-api)
5. [테스트 방법](#테스트-방법)

---

## 개요

Challenge API는 공모전(Contest)과 미션(Mission) 기능을 제공합니다.

### 주요 기능
- ✅ 공모전 조회 및 참가
- ✅ 공모전 제출물 작성 (1인 1제출, 삭제 불가)
- ✅ 제출물에 댓글 및 공감
- ✅ **개인별 미션 자동 할당 및 진행 현황 추적**
- ✅ 미션 자동 갱신 (주간: 매주 일요일 00:00, 월간: 매월 1일 00:00)
- ✅ 자동 미션 진행도 업데이트 (제출물 작성, 공감, 댓글 작성 시)

### 인증
- 대부분의 API는 JWT 인증이 필요합니다.
- 공모전 목록/상세 조회는 인증 불필요

```
Authorization: Bearer {JWT_TOKEN}
```

---

## API 엔드포인트

### Contest API
| Method | Endpoint | 설명 | 인증 |
|--------|----------|------|------|
| GET | `/v0/contests` | 진행 중인 공모전 목록 | ❌ |
| GET | `/v0/contests/{contestId}` | 공모전 상세 조회 | ❌ |
| POST | `/v0/contests/{contestId}/join` | 공모전 참가 | ✅ |
| GET | `/v0/contests/my` | 내가 참가한 공모전 목록 | ✅ |
| POST | `/v0/contests/{contestId}/posts` | 제출물 작성 | ✅ |
| GET | `/v0/contests/{contestId}/posts` | 제출물 목록 조회 | ❌ |
| GET | `/v0/contests/{contestId}/posts/{postId}` | 제출물 상세 조회 | ❌ |
| POST | `/v0/contests/posts/{postId}/comments` | 댓글 작성 | ✅ |
| GET | `/v0/contests/posts/{postId}/comments` | 댓글 목록 조회 | ❌ |
| POST | `/v0/contests/posts/{postId}/empathy` | 공감 추가 | ✅ |
| DELETE | `/v0/contests/posts/{postId}/empathy` | 공감 취소 | ✅ |

### Mission API
| Method | Endpoint | 설명 | 인증 |
|--------|----------|------|------|
| GET | `/v0/missions` | 내 미션 목록 (진행 현황 포함) | ✅ |
| GET | `/v0/missions/completed` | 완료된 미션 목록 | ✅ |

> ⚠️ **중요**: 미션은 사용자별로 자동 할당됩니다. 활성 미션 목록을 조회하는 API는 없으며, 각 사용자는 자신의 미션만 볼 수 있습니다.

---

## Contest API

### 1. 진행 중인 공모전 목록 조회

**Request**
```http
GET /v0/contests
```

**Response**
```json
[
  {
    "contestId": 1,
    "title": "2024 친환경 아이디어 공모전",
    "host": "환경부",
    "description": "친환경 솔루션 아이디어를 공모합니다",
    "startDate": "2024-01-01",
    "endDate": "2024-12-31",
    "reward1st": 1000,
    "reward2nd": 500,
    "reward3rd": 300,
    "rewardDescription": "1등 1000P, 2등 500P, 3등 300P",
    "thumbnailUrl": "https://example.com/thumbnail.jpg",
    "createdAt": "2024-01-01T00:00:00",
    "participantCount": 150,
    "submissionCount": 120
  }
]
```

---

### 2. 공모전 상세 조회

**Request**
```http
GET /v0/contests/1
```

**Response**
```json
{
  "contestId": 1,
  "title": "2024 친환경 아이디어 공모전",
  "host": "환경부",
  "description": "친환경 솔루션 아이디어를 공모합니다",
  "startDate": "2024-01-01",
  "endDate": "2024-12-31",
  "reward1st": 1000,
  "reward2nd": 500,
  "reward3rd": 300,
  "rewardDescription": "1등 1000P, 2등 500P, 3등 300P",
  "thumbnailUrl": "https://example.com/thumbnail.jpg",
  "createdAt": "2024-01-01T00:00:00",
  "participantCount": 150,
  "submissionCount": 120
}
```

---

### 3. 공모전 참가

**Request**
```http
POST /v0/contests/1/join
Authorization: Bearer {JWT_TOKEN}
```

**Response**
```http
201 Created
```

**에러 응답**
```json
{
  "message": "공모전을 찾을 수 없습니다. (contestId: 1)"
}
```

```json
{
  "message": "이미 참가한 공모전입니다."
}
```

---

### 4. 내가 참가한 공모전 목록

**Request**
```http
GET /v0/contests/my
Authorization: Bearer {JWT_TOKEN}
```

**Response**
```json
[
  {
    "contestId": 1,
    "title": "2024 친환경 아이디어 공모전",
    "host": "환경부",
    "description": "친환경 솔루션 아이디어를 공모합니다",
    "startDate": "2024-01-01",
    "endDate": "2024-12-31",
    "participantCount": 150,
    "submissionCount": 120,
    "isParticipant": true
  }
]
```

---

### 5. 제출물 작성 (1인 1제출, 삭제 불가)

**Request**
```http
POST /v0/contests/1/posts
Authorization: Bearer {JWT_TOKEN}
Content-Type: application/json

{
  "title": "플라스틱 재활용 IoT 시스템",
  "content": "AI 기반 플라스틱 분류 시스템을 제안합니다. 이 시스템은...",
  "category": "환경",
  "imagePath": "https://example.com/image1.jpg",
  "fileUrl": "https://example.com/proposal.pdf"
}
```

**필드 설명**
- `title` (필수): 제안 제목 (1-100자)
- `content` (필수): 제출 내용 (1-5000자)
- `category` (선택): 카테고리 (최대 20자)
- `imagePath` (선택): 이미지 URL (최대 500자)
- `fileUrl` (선택): 첨부 파일 URL (최대 255자)

**Response**
```json
{
  "id": 1,
  "contestId": 1,
  "parentPostId": null,
  "userId": "user123",
  "userNickname": "홍길동",
  "title": "플라스틱 재활용 IoT 시스템",
  "content": "AI 기반 플라스틱 분류 시스템을 제안합니다. 이 시스템은...",
  "category": "환경",
  "imagePath": "https://example.com/image1.jpg",
  "fileUrl": "https://example.com/proposal.pdf",
  "empathy": 0,
  "createdAt": "2024-01-15T10:30:00"
}
```

**에러 응답**
```json
{
  "message": "공모전에 참가하지 않았습니다."
}
```

```json
{
  "message": "이미 제출한 공모전입니다."
}
```

**💡 미션 자동 업데이트**
- 제출물 작성 시 `proposal` 카테고리 미션의 진행도가 자동으로 +1 증가합니다.

**⚠️ 주의사항**
- 1인 1제출: 한 공모전에 한 번만 제출 가능
- **제출물은 삭제할 수 없습니다**

---

### 6. 제출물 목록 조회

**Request**
```http
GET /v0/contests/1/posts?page=0&size=20&sort=createdAt,desc
```

**Query Parameters**
- `page`: 페이지 번호 (0부터 시작, 기본값: 0)
- `size`: 페이지 크기 (기본값: 20)
- `sort`: 정렬 기준 (기본값: createdAt,desc)

**Response**
```json
{
  "content": [
    {
      "id": 1,
      "contestId": 1,
      "userId": "user123",
      "userNickname": "홍길동",
      "title": "플라스틱 재활용 IoT 시스템",
      "content": "AI 기반 플라스틱 분류 시스템을 제안합니다...",
      "empathy": 15,
      "createdAt": "2024-01-15T10:30:00"
    }
  ],
  "pageable": {
    "pageNumber": 0,
    "pageSize": 20
  },
  "totalElements": 120,
  "totalPages": 6,
  "last": false
}
```

---

### 7. 제출물 상세 조회

**Request**
```http
GET /v0/contests/1/posts/1
```

**Response**
```json
{
  "id": 1,
  "contestId": 1,
  "parentPostId": null,
  "userId": "user123",
  "userNickname": "홍길동",
  "title": "플라스틱 재활용 IoT 시스템",
  "content": "AI 기반 플라스틱 분류 시스템을 제안합니다. 이 시스템은...",
  "category": "환경",
  "imagePath": "https://example.com/image1.jpg",
  "fileUrl": "https://example.com/proposal.pdf",
  "empathy": 15,
  "createdAt": "2024-01-15T10:30:00"
}
```

---

### 8. 댓글 작성

**Request**
```http
POST /v0/contests/posts/1/comments
Authorization: Bearer {JWT_TOKEN}
Content-Type: application/json

{
  "content": "정말 좋은 아이디어네요! 실현 가능성도 높아 보입니다."
}
```

**Response**
```json
{
  "id": 2,
  "contestId": 1,
  "parentPostId": 1,
  "userId": "user456",
  "userNickname": "김철수",
  "title": "플라스틱 재활용 IoT 시스템",  // 부모의 제목 상속
  "content": "정말 좋은 아이디어네요! 실현 가능성도 높아 보입니다.",
  "category": "환경",  // 부모의 카테고리 상속
  "imagePath": null,
  "fileUrl": null,
  "empathy": 0,
  "createdAt": "2024-01-15T11:00:00"
}
```

**💡 미션 자동 업데이트**
- 댓글 작성 시 `comment` 카테고리 미션의 진행도가 자동으로 +1 증가합니다.

---

### 9. 댓글 목록 조회

**Request**
```http
GET /v0/contests/posts/1/comments?page=0&size=20&sort=createdAt,asc
```

**Response**
```json
{
  "content": [
    {
      "id": 2,
      "contestId": 1,
      "parentPostId": 1,
      "userId": "user456",
      "userNickname": "김철수",
      "content": "정말 좋은 아이디어네요!",
      "empathy": 3,
      "createdAt": "2024-01-15T11:00:00"
    }
  ],
  "totalElements": 8,
  "totalPages": 1,
  "last": true
}
```

---

### 10. 공감 추가

**Request**
```http
POST /v0/contests/posts/1/empathy
Authorization: Bearer {JWT_TOKEN}
```

**Response**
```http
200 OK
```

**💡 미션 자동 업데이트**
- 공감 추가 시 `empathy` 카테고리 미션의 진행도가 자동으로 +1 증가합니다.

---

### 11. 공감 취소

**Request**
```http
DELETE /v0/contests/posts/1/empathy
Authorization: Bearer {JWT_TOKEN}
```

**Response**
```http
200 OK
```

---

## Mission API

### ℹ️ 미션 개요

- 미션은 **사용자별로 자동 할당**됩니다
- 각 사용자는 **자신의 미션만** 조회할 수 있습니다
- 미션 진행도는 사용자 행동에 따라 **자동으로 업데이트**됩니다
  - 제출물 작성 → `proposal` 미션 +1
  - 공감 추가 → `empathy` 미션 +1
  - 댓글 작성 → `comment` 미션 +1
- 미션은 **자동으로 갱신**됩니다
  - 주간 미션: 매주 일요일 00:00
  - 월간 미션: 매월 1일 00:00

---

### 1. 내 미션 목록 조회 (진행 현황 포함)

**Request**
```http
GET /v0/missions
Authorization: Bearer {JWT_TOKEN}
```

**Response**
```json
[
  {
    "missionId": 1,
    "title": "제안 작성 미션",
    "description": "공모전에 3개 이상의 제안을 작성하세요",
    "goalCount": 3,
    "category": "proposal",
    "periodType": "weekly",
    "startDate": "2024-01-01",
    "endDate": "2024-01-07",
    "rewardPoints": 100,
    "createdAt": "2024-01-01T00:00:00",
    "currentCount": 2,  // 현재 진행 횟수
    "completed": false  // 완료 여부
  },
  {
    "missionId": 2,
    "title": "공감 미션",
    "description": "다른 사람의 제안에 10번 공감하세요",
    "goalCount": 10,
    "category": "empathy",
    "periodType": "weekly",
    "startDate": "2024-01-01",
    "endDate": "2024-01-07",
    "rewardPoints": 50,
    "createdAt": "2024-01-01T00:00:00",
    "currentCount": 10,  // 완료!
    "completed": true
  }
]
```

**응답 필드 설명**
- `missionId`: 미션 ID
- `title`: 미션 제목
- `description`: 미션 설명
- `goalCount`: 목표 달성 횟수
- `category`: 미션 카테고리 (`proposal`, `empathy`, `comment`)
- `periodType`: 기간 타입 (`weekly`, `monthly`)
- `startDate`: 미션 시작일
- `endDate`: 미션 종료일
- `rewardPoints`: 완료 시 보상 포인트
- `currentCount`: **내 현재 진행 횟수**
- `completed`: **내 완료 여부**

---

### 2. 완료된 미션 목록

**Request**
```http
GET /v0/missions/completed
Authorization: Bearer {JWT_TOKEN}
```

**Response**
```json
[
  {
    "id": 2,
    "missionId": 2,
    "missionTitle": "공감 미션",
    "userId": "user123",
    "currentCount": 10,
    "goalCount": 10,
    "completed": true,
    "completedAt": "2024-01-15T11:00:00",
    "updatedAt": "2024-01-15T11:00:00",
    "progressPercentage": 100
  }
]
```

**응답 필드 설명**
- `id`: 진행 현황 ID
- `missionId`: 미션 ID
- `missionTitle`: 미션 제목
- `userId`: 사용자 ID (본인)
- `currentCount`: 현재 진행 횟수
- `goalCount`: 목표 횟수
- `completed`: 완료 여부
- `completedAt`: 완료 시각
- `updatedAt`: 마지막 업데이트 시각
- `progressPercentage`: 진행률 (%)

---

## 테스트 방법

### 1️⃣ 환경 준비

#### Docker로 실행 (권장)
```bash
# 전체 스택 실행
docker-compose up -d

# 로그 확인
docker-compose logs -f app
```

#### 로컬에서 실행
```bash
# 데이터베이스만 Docker로 실행
docker-compose up -d mysql redis

# 환경 변수 설정 (Windows)
set MYSQL_HOST=localhost
set DB_NAME=content_db
set SPRING_DATASOURCE_PASSWORD=root1234
set REDIS_HOST=localhost
set REDIS_PORT=6379

# 환경 변수 설정 (Linux/Mac)
export MYSQL_HOST=localhost
export DB_NAME=content_db
export SPRING_DATASOURCE_PASSWORD=root1234
export REDIS_HOST=localhost
export REDIS_PORT=6379

# 애플리케이션 실행
./gradlew bootRun
```

---

### 2️⃣ 데이터베이스에 테스트 데이터 삽입

MySQL에 접속하여 테스트 데이터를 삽입합니다:

```bash
# Docker로 MySQL 접속
docker exec -it miyo-mysql mysql -u root -proot1234 content_db
```

**공모전 데이터 삽입**
```sql
-- 공모전 생성
INSERT INTO ContestData (title, host, description, start_date, end_date, reward_1st, reward_2nd, reward_3rd, reward_description, thumbnail_url)
VALUES
('2024 친환경 아이디어 공모전', '환경부', '친환경 솔루션 아이디어를 공모합니다', '2024-01-01', '2024-12-31', 1000, 500, 300, '1등 1000P, 2등 500P, 3등 300P', 'https://example.com/thumbnail1.jpg'),
('스마트시티 혁신 공모전', '국토교통부', '스마트시티 관련 혁신 아이디어 공모', '2024-01-01', '2024-12-31', 2000, 1000, 500, '1등 2000P, 2등 1000P, 3등 500P', 'https://example.com/thumbnail2.jpg');

-- 확인
SELECT * FROM ContestData;
```

**미션 데이터 삽입**
```sql
-- 주간 미션 생성
INSERT INTO Mission (title, description, goal_count, category, period_type, start_date, end_date, reward_points)
VALUES
('제안 작성 미션', '공모전에 3개 이상의 제안을 작성하세요', 3, 'proposal', 'weekly', '2024-01-01', '2024-12-31', 100),
('공감 미션', '다른 사람의 제안에 10번 공감하세요', 10, 'empathy', 'weekly', '2024-01-01', '2024-12-31', 50),
('댓글 미션', '다른 사람의 제안에 5개 이상의 댓글을 작성하세요', 5, 'comment', 'weekly', '2024-01-01', '2024-12-31', 30);

-- 월간 미션 생성
INSERT INTO Mission (title, description, goal_count, category, period_type, start_date, end_date, reward_points)
VALUES
('월간 제안왕', '한 달에 10개 이상의 제안을 작성하세요', 10, 'proposal', 'monthly', '2024-01-01', '2024-12-31', 500);

-- 확인
SELECT * FROM Mission;
```

---

### 3️⃣ Swagger UI로 테스트 (가장 쉬움!)

브라우저에서 다음 주소로 접속:
```
http://localhost:8080/swagger-ui/index.html
```

Swagger UI에서:
1. **Authorize** 버튼 클릭
2. JWT 토큰 입력 (임시로 아무 값이나 넣어도 테스트 가능)
3. API를 선택하고 **Try it out** 클릭
4. 파라미터 입력 후 **Execute** 클릭

---

### 4️⃣ cURL로 테스트

#### 1. 공모전 목록 조회 (인증 불필요)
```bash
curl http://localhost:8080/v0/contests
```

#### 2. 공모전 상세 조회 (인증 불필요)
```bash
curl http://localhost:8080/v0/contests/1
```

#### 3. 공모전 참가
```bash
curl -X POST http://localhost:8080/v0/contests/1/join \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### 4. 제출물 작성
```bash
curl -X POST http://localhost:8080/v0/contests/1/posts \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "플라스틱 재활용 IoT 시스템",
    "content": "AI 기반 플라스틱 분류 시스템을 제안합니다. 이 시스템은 카메라와 AI를 활용하여 플라스틱 종류를 자동으로 분류합니다.",
    "category": "환경",
    "imagePath": "https://example.com/image1.jpg"
  }'
```

#### 5. 내 미션 목록 확인
```bash
curl http://localhost:8080/v0/missions \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### 6. 공감 추가
```bash
curl -X POST http://localhost:8080/v0/contests/posts/1/empathy \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### 7. 댓글 작성
```bash
curl -X POST http://localhost:8080/v0/contests/posts/1/comments \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "정말 좋은 아이디어네요! 실현 가능성도 높아 보입니다."
  }'
```

---

### 5️⃣ 전체 시나리오 테스트

#### 시나리오 1: 공모전 참가 및 제출 → 미션 자동 업데이트
```bash
# 1. 공모전 목록 조회
curl http://localhost:8080/v0/contests

# 2. 공모전 상세 조회
curl http://localhost:8080/v0/contests/1

# 3. 공모전 참가
curl -X POST http://localhost:8080/v0/contests/1/join \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# 4. 제출물 작성 (미션 자동 업데이트: proposal +1)
curl -X POST http://localhost:8080/v0/contests/1/posts \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "제목",
    "content": "내용"
  }'

# 5. 내 미션 확인 (proposal 미션의 currentCount가 +1 증가)
curl http://localhost:8080/v0/missions \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### 시나리오 2: 미션 완료하기
```bash
# 1. 내 미션 확인
curl http://localhost:8080/v0/missions \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# 2. 다른 사람 제출물에 공감 (10번 반복하여 미션 완료)
for i in {1..10}; do
  curl -X POST http://localhost:8080/v0/contests/posts/1/empathy \
    -H "Authorization: Bearer YOUR_JWT_TOKEN"
  sleep 1
done

# 3. 완료된 미션 확인
curl http://localhost:8080/v0/missions/completed \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

## 🔍 디버깅 팁

### 로그 확인
```bash
# Docker 로그
docker-compose logs -f app

# 미션 진행도 업데이트 로그 확인
docker-compose logs -f app | grep -i mission
```

### 데이터베이스 확인
```bash
# MySQL 접속
docker exec -it miyo-mysql mysql -u root -proot1234 content_db

# 테이블 확인
SHOW TABLES;

# 내 미션 진행 현황 확인
SELECT * FROM UserMissionProgress WHERE user_id = 'test-user-123';

# 미션 정의 확인
SELECT * FROM Mission;

# 공모전 확인
SELECT * FROM ContestData;
```

---

## 📊 응답 코드

| 코드 | 의미 | 설명 |
|------|------|------|
| 200 | OK | 성공 |
| 201 | Created | 리소스 생성 성공 |
| 204 | No Content | 삭제 성공 |
| 400 | Bad Request | 잘못된 요청 (유효성 검증 실패) |
| 401 | Unauthorized | 인증 실패 |
| 403 | Forbidden | 권한 없음 |
| 404 | Not Found | 리소스를 찾을 수 없음 |
| 500 | Internal Server Error | 서버 오류 |

---

## ⚠️ 주의사항

1. **1인 1제출 제약**: 한 공모전에 한 번만 제출 가능
2. **제출물 삭제 불가**: 한 번 제출한 제출물은 삭제할 수 없습니다
3. **JWT 필수**: 인증이 필요한 API는 반드시 JWT 토큰 필요
4. **미션 자동 할당**: 사용자가 활동을 시작하면 자동으로 미션이 할당됩니다
5. **미션 자동 업데이트**: 제출물 작성, 공감, 댓글 작성 시 자동으로 미션 진행도 업데이트
6. **미션 자동 갱신**:
   - 주간 미션: 매주 일요일 00:00 리셋
   - 월간 미션: 매월 1일 00:00 리셋
7. **개인별 미션**: 각 사용자는 자신의 미션만 조회 가능
8. **페이징**: 목록 조회 시 기본 20개씩 페이징

---

## 🆘 문제 해결

### Q: JWT 토큰이 없는데 어떻게 테스트하나요?
A: Swagger UI에서 임시 토큰으로 테스트하거나, User Service에서 토큰을 발급받으세요.

### Q: 미션 진행도가 업데이트되지 않아요
A: 로그를 확인하여 MissionValidator가 제대로 실행되는지 확인하세요.
```bash
docker-compose logs -f app | grep -i mission
```

### Q: 공모전 참가가 안돼요
A: 공모전이 존재하는지, 이미 참가하지 않았는지 확인하세요.

### Q: 제출물을 두 번 작성할 수 없어요
A: 1인 1제출 제약이 있습니다. 한 공모전에 한 번만 제출 가능합니다.

### Q: 제출물을 삭제하고 싶어요
A: 제출물은 삭제할 수 없습니다. 신중하게 작성해주세요.

### Q: 내 미션이 보이지 않아요
A: 미션은 사용자가 활동(제출물 작성, 공감 등)을 시작할 때 자동으로 할당됩니다.

---

## 📚 참고 자료

- [DOCKER.md](DOCKER.md) - Docker 환경 설정 가이드
- [Swagger UI](http://localhost:8080/swagger-ui/index.html) - API 문서
- [OpenAPI JSON](http://localhost:8080/v3/api-docs) - API 스펙

---

**Happy Testing! 🎉**
