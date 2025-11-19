# Keycloak OAuth2 Learning Project

이 프로젝트는 로컬에서 Keycloak을 도커로 띄운 뒤 OAuth2 Authorization Code (PKCE 포함) 흐름을 학습하기 위한 최소 예제입니다.

구성요소
- Keycloak (docker-compose)
- 간단한 Node.js 샘플 앱 (Express) for Authorization Code flow

빠른 시작
1. 도커 컴포즈로 Keycloak 시작

```powershell
docker compose up -d
```

2. 브라우저에서 http://localhost:8080 접속 후 Admin Console에서 Realm, Client, User 생성

권장 설정
- Realm: `myrealm`
- Client: `my-client` (Client type: openid-connect), Redirect URI: `http://localhost:3000/callback`
- Client에서 `client secret`을 발급받아 `.env`에 설정하거나 public client로 PKCE 사용


**작업 진행 프로세스 기록** 
- Keycloak 설정 및 도커 컴포즈 파일 작성 및 실행
- Node.js 샘플 앱 개발 시작
- keycloak realm resource export json 작성 -> 키클록 콘솔 브라우저를 통해 사용 가능