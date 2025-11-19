# sso-oauth2-server-2

SSO test server 2. Simple Express app demonstrating Authorization Code + PKCE against Keycloak.

Usage

```powershell
cd sso-oauth2-server-2
npm install
cp .env.example .env
# edit .env to match your Keycloak (client id, base url)
npm start
```

Open http://localhost:3002 and click Log in with Keycloak. If you already have a Keycloak session from another app, Keycloak will usually skip login and return immediately (SSO behavior).
