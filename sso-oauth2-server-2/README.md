# sso-oauth2-server-2

SSO 테스트 서버 2. Keycloak을 대상으로 Authorization Code + PKCE 흐름을 시연하는 또 다른 간단한 Express 앱입니다.

사용법

```powershell
cd sso-oauth2-server-2
npm install
cp .env.example .env
# .env에서 Keycloak 설정(CLIENT_ID, KEYCLOAK_BASE_URL, REALM 등)을 실제 값으로 수정하세요
npm start
```

브라우저에서 http://localhost:3002 를 열고 "Log in with Keycloak" 버튼을 클릭하세요. 이미 다른 애플리케이션으로 Keycloak 세션이 있는 경우(SSO) 로그인 과정이 생략되고 바로 리다이렉트될 수 있습니다.
