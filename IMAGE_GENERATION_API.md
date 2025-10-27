# Image Generation API

## 개요
Google Gemini AI (Imagen 3 Fast)를 사용한 이미지 생성 API입니다. Post와 Contest 도메인에서 공통으로 사용할 수 있습니다.

---

## 설정

### 1. API 키 설정

`application.properties` 또는 환경 변수에 Gemini API 키를 설정하세요:

```properties
# application.properties
gemini.api-key=your-actual-api-key-here
```

또는 환경 변수로:

```bash
export GEMINI_API_KEY=your-actual-api-key-here
```

### 2. Docker 환경에서 설정

`.env` 파일에 추가:

```env
GEMINI_API_KEY=your-actual-api-key-here
```

`docker-compose.yml`에서 환경 변수 전달:

```yaml
services:
  app:
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
```

---

## API 엔드포인트

### Base URL
```
http://localhost:8080/v0/images
```

---

## 1. 이미지 생성

### Endpoint
```
POST /v0/images/generate
```

### 설명
사용자가 입력한 프롬프트를 기반으로 AI 이미지를 생성합니다.

### 인증
- **필수**: JWT 토큰 (Bearer Token)

### Request Body
```json
{
  "prompt": "A beautiful sunset over the ocean with palm trees",
  "numberOfImages": 1,
  "size": "1024x1024"
}
```

#### 파라미터 설명

| 필드 | 타입 | 필수 | 기본값 | 설명 |
|------|------|------|--------|------|
| `prompt` | String | ✅ | - | 이미지 생성 프롬프트 (최대 1000자) |
| `numberOfImages` | Integer | ❌ | 1 | 생성할 이미지 개수 |
| `size` | String | ❌ | "1024x1024" | 이미지 크기 (256x256, 512x512, 1024x1024) |

### Response (성공)
```json
{
  "images": [
    "base64_encoded_image_data_here..."
  ],
  "success": true,
  "errorMessage": null,
  "prompt": "A beautiful sunset over the ocean with palm trees"
}
```

### Response (실패)
```json
{
  "images": null,
  "success": false,
  "errorMessage": "이미지 생성 중 오류가 발생했습니다: API key is invalid",
  "prompt": "A beautiful sunset over the ocean with palm trees"
}
```

### Status Codes
- `200 OK`: 이미지 생성 성공
- `500 Internal Server Error`: 이미지 생성 실패
- `400 Bad Request`: 잘못된 요청 (프롬프트 누락 등)
- `401 Unauthorized`: 인증 실패

---

## 2. 헬스체크

### Endpoint
```
GET /v0/images/health
```

### 설명
이미지 생성 서비스 상태 확인

### 인증
- 필수 아님

### Response
```
Image generation service is running
```

---

## 테스트 방법

### 1. Swagger UI 사용
브라우저에서 Swagger UI에 접속:
```
http://localhost:8080/swagger-ui/index.html
```

1. `/v0/images/generate` 엔드포인트 선택
2. "Try it out" 버튼 클릭
3. JWT 토큰 입력 (Authorize 버튼 클릭하여 설정)
4. Request Body 입력:
   ```json
   {
     "prompt": "A cute cat sitting on a sofa",
     "numberOfImages": 1,
     "size": "512x512"
   }
   ```
5. "Execute" 버튼 클릭

### 2. cURL 사용

먼저 JWT 토큰 발급 (로그인):
```bash
# 회원가입 (이미 계정이 없다면)
curl -X POST http://localhost:8080/v0/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "01012345678",
    "password": "password123",
    "nickname": "testuser"
  }'

# 로그인하여 JWT 토큰 받기
TOKEN=$(curl -X POST http://localhost:8080/v0/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "01012345678",
    "password": "password123"
  }' | jq -r '.accessToken')

echo "Token: $TOKEN"
```

이미지 생성 요청:
```bash
curl -X POST http://localhost:8080/v0/images/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "prompt": "A futuristic city with flying cars at night",
    "numberOfImages": 1,
    "size": "1024x1024"
  }' | jq
```

### 3. Postman 사용

1. **Collection 생성**: "Image Generation API" 컬렉션 생성
2. **환경 변수 설정**:
   - `base_url`: `http://localhost:8080`
   - `token`: (로그인 후 받은 JWT 토큰)

3. **요청 생성**:
   - Method: POST
   - URL: `{{base_url}}/v0/images/generate`
   - Headers:
     - `Content-Type`: `application/json`
     - `Authorization`: `Bearer {{token}}`
   - Body (raw JSON):
     ```json
     {
       "prompt": "A peaceful mountain landscape with snow",
       "numberOfImages": 1,
       "size": "1024x1024"
     }
     ```

---

## 사용 시나리오

### 시나리오 1: Post에서 이미지 생성
사용자가 게시글을 작성하면서 AI 이미지를 생성하는 경우:

1. 사용자가 프롬프트 입력: "맛있는 라면 사진"
2. `/v0/images/generate` API 호출
3. 받은 이미지를 서버에 저장 또는 URL로 변환
4. 게시글 작성 시 `imagePath`에 포함

### 시나리오 2: Contest에서 이미지 생성
공모전 제출물에 AI 이미지를 포함하는 경우:

1. 사용자가 제출물 작성 화면에서 프롬프트 입력
2. `/v0/images/generate` API 호출
3. 받은 이미지를 제출물에 첨부
4. `/v0/contests/{contestId}/posts` API로 제출

---

## 에러 처리

### 일반적인 에러

| 에러 | 원인 | 해결 방법 |
|------|------|----------|
| API key is invalid | 잘못된 API 키 | `application.properties`에서 올바른 API 키 설정 |
| Prompt is required | 프롬프트 누락 | Request Body에 `prompt` 필드 추가 |
| Unauthorized | JWT 토큰 누락/만료 | 로그인하여 새 토큰 발급 |
| Service unavailable | Gemini API 서버 문제 | 잠시 후 재시도 |

### 로그 확인
서버 로그에서 상세 에러 확인:
```bash
# Docker 환경
docker-compose logs -f app

# 로컬 환경
./gradlew bootRun
```

---

## 가격 정보

현재 **Imagen 3 Fast** 모델을 사용하여 가장 저렴한 비용으로 이미지를 생성합니다.

Google Cloud Pricing 참고:
- https://cloud.google.com/vertex-ai/pricing

---

## 기술 스택

- **AI Model**: Google Gemini AI (Imagen 3 Fast)
- **Framework**: Spring Boot 3.5.5
- **Authentication**: JWT (Spring Security)
- **HTTP Client**: RestTemplate
- **JSON Parsing**: Jackson ObjectMapper

---

## 주의사항

1. **API 키 보안**: API 키는 절대 코드에 하드코딩하지 말고 환경 변수로 관리하세요.
2. **Rate Limiting**: Gemini API의 사용량 제한을 확인하고 적절히 조절하세요.
3. **이미지 저장**: 생성된 이미지는 Base64 형태로 반환되므로, 필요시 서버에 저장하거나 클라우드 스토리지에 업로드하세요.
4. **프롬프트 검증**: 부적절한 프롬프트를 필터링하는 로직을 추가할 수 있습니다.

---

## 확장 가능성

### 향후 개선 사항
- [ ] 프롬프트 필터링 (부적절한 콘텐츠 차단)
- [ ] 이미지 자동 저장 기능 (S3, NCP Object Storage 등)
- [ ] 이미지 캐싱 (동일한 프롬프트에 대한 재사용)
- [ ] 생성 히스토리 저장
- [ ] 다양한 이미지 스타일 옵션 추가

---

## 문의

문제가 발생하거나 개선 사항이 있다면 이슈를 등록해주세요.
