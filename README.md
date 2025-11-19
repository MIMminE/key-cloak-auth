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

추가 패키지 설명
- simple-oauth2-server: OAuth2 기본 동작(Authorization Code 교환, 토큰 엔드포인트 동작 등)을 간단히 테스트하기 위해 만든 샘플 서버입니다.
- sso-oauth2-server-1: Keycloak과 연동해 SSO(싱글 사인온) 동작을 확인하기 위한 Express 샘플 앱(포트 예: 3001). Authorization Code + PKCE 흐름을 시연합니다.
- sso-oauth2-server-2: SSO 동작을 추가로 테스트하거나 멀티 앱 시나리오를 검증하기 위한 보조 샘플 앱(포트 예: 3002). 