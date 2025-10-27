# Docker 환경 설정 가이드

## 사전 요구사항
- Docker Desktop 설치
- Docker Compose 설치

## 빠른 시작

### 1. Docker Compose로 전체 스택 실행 (권장)

```bash
# MySQL, Redis, Spring Boot 앱 모두 실행
docker-compose up -d

# 로그 확인
docker-compose logs -f

# 중지
docker-compose down

# 볼륨까지 삭제 (데이터 초기화)
docker-compose down -v
```

### 2. 데이터베이스만 실행 (로컬 개발 시)

```bash
# MySQL과 Redis만 실행
docker-compose up -d mysql redis

# 로컬에서 Spring Boot 실행
./gradlew bootRun
```

## 환경 변수 설정

`.env.example` 파일을 참고하여 `.env` 파일을 생성할 수 있습니다:

```bash
cp .env.example .env
```

### 환경 변수 목록

| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `MYSQL_HOST` | MySQL 호스트 | `mysql` (Docker), `localhost` (로컬) |
| `DB_NAME` | 데이터베이스 이름 | `content_db` |
| `SPRING_DATASOURCE_PASSWORD` | MySQL root 비밀번호 | `root1234` |
| `REDIS_HOST` | Redis 호스트 | `redis` (Docker), `localhost` (로컬) |
| `REDIS_PORT` | Redis 포트 | `6379` |
| `jwtSecret` | JWT 시크릿 키 (Base64) | 기본값 제공 |

## 데이터베이스 초기화

Docker Compose 실행 시 자동으로 다음 스크립트들이 실행됩니다:

1. `init-db.sql` - Community 도메인 테이블 생성
   - `posts_write` (Write Model)
   - `posts_read` (Read Model)
   - `empathy_data` (공감 데이터)

2. `init-db-challenge.sql` - Challenge 도메인 테이블 생성
   - `ContestData` (공모전 메타데이터)
   - `ContestUser` (공모전 참가자)
   - `ContestPost` (공모전 제출물)
   - `Mission` (미션 정의)
   - `UserMissionProgress` (유저별 미션 진행 현황)

## 서비스 포트

| 서비스 | 포트 | 설명 |
|--------|------|------|
| Spring Boot | 8080 | REST API 서버 |
| MySQL | 3306 | 데이터베이스 |
| Redis | 6379 | 캐시/이벤트 스트림 |

## API 문서 (Swagger)

애플리케이션 실행 후 다음 URL에서 API 문서를 확인할 수 있습니다:

- Swagger UI: http://localhost:8080/swagger-ui/index.html
- OpenAPI JSON: http://localhost:8080/v3/api-docs

## 데이터베이스 접속

### Docker 컨테이너를 통한 접속

```bash
# MySQL 접속
docker exec -it miyo-mysql mysql -u root -proot1234 content_db

# Redis 접속
docker exec -it miyo-redis redis-cli
```

### 로컬 클라이언트를 통한 접속

- **MySQL**
  - Host: `localhost`
  - Port: `3306`
  - Database: `content_db`
  - User: `root`
  - Password: `root1234`

- **Redis**
  - Host: `localhost`
  - Port: `6379`

## 트러블슈팅

### 포트 충돌 문제

```bash
# MySQL 포트 충돌 (3306)
# 로컬 MySQL 중지
net stop MySQL80  # Windows
sudo systemctl stop mysql  # Linux/Mac

# Redis 포트 충돌 (6379)
# 로컬 Redis 중지
# Windows: 서비스에서 중지
sudo systemctl stop redis  # Linux/Mac
```

### 빌드 실패 시

```bash
# Gradle 캐시 삭제
./gradlew clean

# Docker 이미지 재빌드
docker-compose build --no-cache

# 모든 컨테이너와 볼륨 삭제 후 재시작
docker-compose down -v
docker-compose up -d --build
```

### 데이터베이스 초기화가 안될 때

```bash
# 볼륨 삭제 후 재시작
docker-compose down -v
docker-compose up -d
```

## 로그 확인

```bash
# 모든 서비스 로그
docker-compose logs -f

# 특정 서비스 로그만 확인
docker-compose logs -f app
docker-compose logs -f mysql
docker-compose logs -f redis

# 최근 100줄만 확인
docker-compose logs --tail=100 -f app
```

## 컨테이너 상태 확인

```bash
# 실행 중인 컨테이너 확인
docker-compose ps

# 헬스체크 상태 확인
docker-compose ps mysql redis

# 리소스 사용량 확인
docker stats miyo-backend miyo-mysql miyo-redis
```

## 개발 워크플로우

### 로컬 개발 시 (권장)

```bash
# 1. 데이터베이스만 Docker로 실행
docker-compose up -d mysql redis

# 2. 로컬에서 Spring Boot 실행 (핫 리로드 지원)
./gradlew bootRun

# 3. 코드 수정 후 자동 재시작
```

### 전체 Docker 환경에서 개발

```bash
# 1. 코드 수정
# 2. 재빌드 및 재시작
docker-compose up -d --build app

# 또는 더 빠르게
docker-compose restart app
```

## Production 배포

Production 환경에서는 다음 사항을 고려하세요:

1. **환경 변수 보안**: `.env` 파일 대신 시크릿 관리 시스템 사용
2. **데이터베이스 백업**: MySQL 볼륨 정기 백업
3. **로그 관리**: 로그 수집 시스템 연동 (ELK, CloudWatch 등)
4. **모니터링**: Prometheus, Grafana 등 모니터링 도구 연동
5. **리소스 제한**: docker-compose.yml에 resource limits 추가

```yaml
app:
  # ...
  deploy:
    resources:
      limits:
        cpus: '1.0'
        memory: 1G
      reservations:
        cpus: '0.5'
        memory: 512M
```
