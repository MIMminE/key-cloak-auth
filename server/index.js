// Minimal Express server demonstrating Authorization Code + PKCE with Keycloak
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const pkceChallenge = require('pkce-challenge');
const qs = require('querystring');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

const KEYCLOAK_BASE_URL = process.env.KEYCLOAK_BASE_URL || 'http://localhost:8080';
const REALM = process.env.KEYCLOAK_REALM || 'myrealm';
const CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || 'my-client';
const CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET || '';
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${port}`;

app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));

app.get('/', (req, res) => {
  res.send(`<h2>Keycloak PKCE Demo</h2>
  <a href="/login">Log in with Keycloak</a>`);
});

app.get('/login', (req, res) => {
  const { code_challenge, code_verifier } = pkceChallenge();
  req.session.code_verifier = code_verifier;

  const params = {
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: `${APP_BASE_URL}/callback`,
    scope: 'openid profile email',
    code_challenge,
    code_challenge_method: 'S256'
  };

  const authUrl = `${KEYCLOAK_BASE_URL}/realms/${REALM}/protocol/openid-connect/auth?${qs.stringify(params)}`;
  res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing code');

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

    res.send(`<h2>Logged in</h2>
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
    res.send(`<h2>User info</h2><pre>${JSON.stringify(resp.data, null, 2)}</pre>`);
  } catch (err) {
    console.error(err.response ? err.response.data : err.message);
    res.status(500).send('Failed to fetch userinfo');
  }
});

app.listen(port, () => console.log(`Server listening on ${port}`));

