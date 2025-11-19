// sso-oauth2-server-1: Minimal Express server demonstrating Authorization Code + PKCE with Keycloak
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const pkceChallenge = require('pkce-challenge');
const qs = require('querystring');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const app = express();
const port = process.env.SERVER_PORT || 3001;

const KEYCLOAK_BASE_URL = process.env.KEYCLOAK_BASE_URL || 'http://localhost:8080';
const REALM = process.env.KEYCLOAK_REALM || 'myrealm';
const CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || 'sso-client-1';
const CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET || '';
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${port}`;
const SESSION_SECRET = process.env.SESSION_SECRET || 'keyboard cat 1';

app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: true }));

app.get('/', (req, res) => {
  res.send(`<h2>SSO Server 1 (port ${port})</h2>
  <a href="/login">Log in with Keycloak</a><br/>
  <a href="/profile">Profile (if logged in)</a>`);
});

app.get('/login', (req, res) => {
  const { code_challenge, code_verifier } = pkceChallenge();
  req.session.code_verifier = code_verifier;
  const state = uuidv4();
  req.session.state = state;

  const params = {
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: `${APP_BASE_URL}/callback`,
    scope: 'openid profile email',
    code_challenge,
    code_challenge_method: 'S256',
    state
  };

  const authUrl = `${KEYCLOAK_BASE_URL}/realms/${REALM}/protocol/openid-connect/auth?${qs.stringify(params)}`;
  res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send('Missing code');
  if (!state || state !== req.session.state) return res.status(400).send('Invalid state');

  try {
    const tokenUrl = `${KEYCLOAK_BASE_URL}/realms/${REALM}/protocol/openid-connect/token`;

    const data = {
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      redirect_uri: `${APP_BASE_URL}/callback`,
      code,
      code_verifier: req.session.code_verifier
    };

    if (CLIENT_SECRET) data.client_secret = CLIENT_SECRET;

    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

    const resp = await axios.post(tokenUrl, qs.stringify(data), { headers });

    req.session.token = resp.data;
    // token contains access_token, id_token, refresh_token (if enabled)

    res.send(`<h2>Logged in (Server 1)</h2>
    <pre>${JSON.stringify(resp.data, null, 2)}</pre>
    <a href="/profile">View profile</a>`);
  } catch (err) {
    console.error(err.response ? err.response.data : err.message);
    res.status(500).send('Token exchange failed');
  }
});

app.get('/profile', async (req, res) => {
  if (!req.session.token) return res.redirect('/');
  try {
    const userinfoUrl = `${KEYCLOAK_BASE_URL}/realms/${REALM}/protocol/openid-connect/userinfo`;
    const resp = await axios.get(userinfoUrl, { headers: { Authorization: `Bearer ${req.session.token.access_token}` } });
    res.send(`<h2>User info (Server 1)</h2><pre>${JSON.stringify(resp.data, null, 2)}</pre>`);
  } catch (err) {
    console.error(err.response ? err.response.data : err.message);
    res.status(500).send('Failed to fetch userinfo');
  }
});

app.listen(port, () => console.log(`SSO Server 1 listening on ${port}`));
