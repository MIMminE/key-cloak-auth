# Keycloak Sample Server

이 Express 앱은 Keycloak과 Authorization Code + PKCE 흐름을 간단히 시연합니다.

설치

```powershell
cd server
npm install
cp .env.example .env
# .env에서 설정을 수정하세요
npm start
```

동작
1. http://localhost:3000 접속
2. Log in with Keycloak 클릭 -> Keycloak 로그인/콘솔로 이동
3. 로그인 후 토큰 확인 및 /profile에서 userinfo 확인

환경변수
- KEYCLOAK_BASE_URL: Keycloak 주소, 기본값 http://localhost:8080
- KEYCLOAK_REALM: realm 이름 (myrealm)
- KEYCLOAK_CLIENT_ID: client id
- KEYCLOAK_CLIENT_SECRET: (confidential client인 경우)
- APP_BASE_URL: 앱 본인 주소 (예: http://localhost:3000)

## 코드 리뷰: index.js — Keycloak과 통신하여 토큰을 얻어오는 프로세스

아래는 index.js(Express 앱)에서 Keycloak과 Authorization Code (+ PKCE) 흐름으로 토큰을 얻는 과정을 검토한 내용입니다. 적용 가능한 체크리스트와 권장 변경사항을 간단히 정리했습니다.

1) 전체 흐름(요약)
- 사용자 -> /login (클라이언트) -> Keycloak authorize endpoint로 리디렉션 (response_type=code, client_id, redirect_uri, scope, state, code_challenge(=PKCE) 등)
- Keycloak 로그인 후 redirect_uri로 code + state 반환
- 서버(index.js)에서 code를 받아 token endpoint에 POST (grant_type=authorization_code, code, redirect_uri, client_id, code_verifier, client_secret(환경에 따라))
- token 응답(access_token, id_token, refresh_token 등)을 받고 필요한 검증을 수행한 뒤 사용자 세션을 생성하거나 토큰을 반환

2) 반드시 확인할 항목 (핵심)
- state 파라미터 검증: CSRF 방지. 요청 시 생성한 state를 콜백에서 비교.
- PKCE: public client인 경우 code_challenge + code_verifier 사용 여부 확인.
- redirect_uri 일치: Keycloak에 등록된 값과 정확히 일치해야 함.
- client_secret 사용: confidential client인 경우 안전한 서버 측 환경변수에서만 사용.
- HTTPS 사용: 프로덕션에서는 반드시 https로 통신.

3) 토큰 검증
- id_token/access_token의 서명 검증: Keycloak의 JWKS (/.well-known/openid-configuration에서 jwks_uri 확인)로 서명(kid, alg) 확인.
- 만료(exp, iat) 및 audience(aud), issuer(iss) 확인.
- scope/claims가 필요한 값(예: profile, email)을 포함하는지 체크.

4) 저장 및 보안
- refresh_token/민감 데이터는 DB에 암호화 저장 또는 안전한 세션 스토리지 사용.
- 브라우저에 토큰을 직접 노출하지 않음. 가능하면 HttpOnly, Secure cookie로 세션 처리.
- SameSite 설정으로 CSRF 위험 최소화.

5) 에러 처리 및 로깅
- 토큰 엔드포인트 응답 오류(body, status)를 상세 로깅(민감 정보는 마스킹).
- 네트워크 실패, invalid_grant(이미 사용된 code), invalid_client 등의 에러 케이스 처리.
- 재시도 정책은 idempotency 고려해서 설계.

6) 성능 및 운영
- JWKS 캐싱: 키 회전 빈도 대비 적절한 TTL로 캐시 후 자동 갱신.
- 토큰 검증 라이브러리 사용 권장(예: node-jsonwebtoken + jwks-rsa 또는 oidc-client 등).

7) 샘플 토큰 교환(간단한 pseudocode)
- POST /protocol/openid-connect/token
  - grant_type=authorization_code
  - code=<받은 code>
  - redirect_uri=<redirect_uri>
  - client_id=<client_id>
  - code_verifier=<pkce_verifier> (있다면)
  - client_secret=<secret> (confidential client인 경우, 서버에서만)

간단 cURL 예:
  curl -X POST '{KEYCLOAK_BASE_URL}/realms/{REALM}/protocol/openid-connect/token' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'grant_type=authorization_code&code=...&redirect_uri=...&client_id=...&code_verifier=...'

8) 흔한 실수와 해결책
- Redirect URI mismatch: Keycloak에 등록된 값과 정확히 비교(슬래시, 포트 포함).
- PKCE 미스매치: code_challenge 생성 방식(S256)과 code_verifier 전달 확인.
- 클라이언트 타임 동기화 문제: 토큰 만료/검증 오류 발생 시 서버 시간 확인(NTP).
- client_secret 노출: 로그/스크린샷에 노출하지 않도록 주의.

권장 개선점(우선순위)
- 토큰 서명 검증 구현(우선): 보안상 필수.
- state/PKCE 적용 및 검증(중요).
- refresh_token 안전 저장 및 재발급 로직(운영).
- JWKS 캐싱과 자동 갱신(운영 안정성).
- 민감 정보(logging) 마스킹 및 환경변수 관리.

위 체크리스트를 index.js의 해당 로직과 대조하여 누락된 부분을 채우면 보안성과 안정성이 크게 향상됩니다.

## index.js 코드 예시와 라인별 리뷰 (실제 코드+권장사항)

아래는 index.js에서 실제로 사용되는 핵심 라우트와 유틸을 축약한 코드 스니펫입니다. 각 블록 아래에 "무엇을 하는지", "실무 권장", "미구현(TODO)"를 간단히 표기했습니다. 실제 파일의 변수/미들웨어(예: express-session 설정)는 프로젝트에 맞게 적용하세요.

1) 세션/미들웨어(간단 예)
```javascript
// 예시: 세션/미들웨어 설정 (파일 상단에 위치)
const session = require('express-session');
// ...existing code...
app.use(session({
  secret: process.env.SESSION_SECRET || 'replace-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));
```
- 역할/핵심: state, code_verifier 등을 서버 세션에 안전하게 저장하기 위한 기본 설정.
- 실무 권장: production에서는 store(redis 등) 사용, session.regenerate()로 로그인 후 세션 재생성.
- TODO: 세션 스토어를 메모리가 아닌 Redis/DB로 변경(필수, 운영).

2) /login 라우트 (state + PKCE 포함)
```javascript
// /login: Keycloak authorize로 리디렉션
app.get('/login', (req, res) => {
  const state = require('crypto').randomBytes(16).toString('hex'); // CSRF 방지
  const { code_challenge, code_verifier } = pkceChallenge();       // pkceChallenge 함수 사용

  // 세션에 저장
  req.session.state = state;
  req.session.code_verifier = code_verifier;

  const params = {
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: `${APP_BASE_URL}/callback`,
    scope: 'openid profile email',
    state,                                 // <-- 반드시 포함
    code_challenge,
    code_challenge_method: 'S256'
  };

  const authUrl = `${KEYCLOAK_BASE_URL}/realms/${REALM}/protocol/openid-connect/auth?${qs.stringify(params)}`;
  res.redirect(authUrl);
});
```
- 역할/핵심: Keycloak로 인증 요청 전송. state는 CSRF 방지, PKCE는 public client 보호.
- 실무 권장: state는 충분히 긴 랜덤값, 세션 TTL 짧게 설정, code_verifier는 검증 후 즉시 삭제.
- TODO: pkceChallenge 구현/검증 로직 확인, 세션 스토어 변경(권장).

3) /callback 라우트 (code 수신 → token 교환)
```javascript
// /callback: authorization code를 받아 token 교환
app.get('/callback', express.urlencoded({ extended: false }), async (req, res) => {
  const { code, state: returnedState } = req.query;

  // CSRF 검증: 세션에 저장한 state와 비교
  if (!req.session || req.session.state !== returnedState) {
    console.warn('Invalid state in callback');
    return res.status(400).send('Invalid state');
  }
  delete req.session.state; // 재사용 차단

  const code_verifier = req.session.code_verifier;
  delete req.session.code_verifier; // 사용 후 삭제 권장

  const tokenUrl = `${KEYCLOAK_BASE_URL}/realms/${REALM}/protocol/openid-connect/token`;
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: `${APP_BASE_URL}/callback`,
    client_id: CLIENT_ID,
    code_verifier
  });

  if (CLIENT_SECRET) body.append('client_secret', CLIENT_SECRET); // confidential client

  const tokenRes = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });

  const tokenData = await tokenRes.json();

  if (!tokenRes.ok) {
    console.error('Token endpoint error', { status: tokenRes.status, body: tokenData });
    return res.status(500).send('Token exchange failed');
  }

  // TODO: id_token 서명 및 클레임 검증(필수)
  // 예: await verifyIdToken(tokenData.id_token);

  // 권장: refresh_token은 DB에 암호화 저장(또는 안전한 세션 스토어)
  // 예: req.session.tokens = { access_token: tokenData.access_token, ... } (주의: 만료관리 필요)
  res.send('로그인 성공 (예시). 세션에 토큰 저장/검증 필요');
});
```
- 역할/핵심: Keycloak에서 받은 code를 token endpoint로 교환하고 응답 처리.
- 실무 권장: 토큰 응답 실패 케이스별(invalid_grant 등) 상세 분기, 민감 정보 로그 마스킹.
- TODO(필수): id_token 서명 검증 및 exp/aud/iss 확인, refresh 토큰 안전 저장.

4) 토큰 검증 플레이스홀더 (JWKS 사용 권장)
```javascript
// verifyIdToken: JWKS를 사용해 id_token 검증(플레이스홀더)
async function verifyIdToken(idToken) {
  // 1) OpenID Configuration 가져와 jwks_uri 조회
  // 2) jwks_uri에서 키를 가져오고 캐시(예: TTL 1시간)
  // 3) kid에 해당하는 공개키로 jwt 검증(alg, exp, iss, aud 등)
  // 권장 라이브러리: jsonwebtoken + jwks-rsa 또는 openid-client
  throw new Error('Not implemented');
}
```
- 역할/핵심: id_token의 서명 및 클레임 검증(보안상 필수).
- 실무 권장: JWKS 캐싱 및 키 회전 처리, 검증 실패 시 로그인 차단.
- TODO(필수): 구현 및 테스트.

5) 에러 처리·로깅·운영 팁(짧게)
- 토큰 엔드포인트 오류(HTTP 상태 + body)를 적절히 분기 처리하고 재시도/대체 경로 설계.
- 로그에는 client_secret, code, refresh_token을 출력하지 말 것(마스킹).
- 서버 시간 동기화(NTP): 토큰 만료 검증 오류 예방.
- SSL(HTTPS) 필수: production에서 http->https 리디렉션 강제.

미구현 항목(TODO, 우선순위)
- [필수] id_token 서명 및 클레임 검증 (verifyIdToken 구현)
- [필수] 세션 스토어를 메모리에서 Redis 등으로 변경
- [권장] refresh_token 암호화 저장 및 refresh 로직 구현
- [권장] JWKS 캐싱/자동갱신
- [권장] session.regenerate() 호출로 세션 고정 방지

체크리스트(코드와 매핑)
- state 생성/검증 -> /login, /callback
- PKCE 생성/검증 -> /login, /callback (code_verifier)
- token 교환 -> /callback (POST to /token)
- id_token 서명 검증 -> verifyIdToken (미구현)
- refresh_token 안전 저장 -> /callback (TODO)
- session 보안(secure, httpOnly, sameSite) -> 세션/미들웨어 블록

간단한 실무 권장 라이브러리
- openid-client: OIDC 흐름을 안전하게 추상화
- jsonwebtoken + jwks-rsa: 직접 검증할 때
- express-session + connect-redis: 세션 저장소
