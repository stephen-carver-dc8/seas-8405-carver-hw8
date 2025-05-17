const express = require('express');
const session = require('express-session');
const Keycloak = require('keycloak-connect');

const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://localhost:8080';
const REALM = process.env.KEYCLOAK_REALM || 'CentralIAM';
const CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || 'intranet';

const memoryStore = new session.MemoryStore();

const app = express();
app.use(session({
  secret: 'a very secret key',
  resave: false,
  saveUninitialized: true,
  store: memoryStore
}));

const keycloak = new Keycloak({ store: memoryStore }, {
  realm: REALM,
  'auth-server-url': `${KEYCLOAK_URL}/realms/${REALM}`,
  resource: CLIENT_ID,
  'public-client': true,
  'confidential-port': 0
});

app.use(keycloak.middleware());

app.get('/', keycloak.protect(), (req, res) => {
  const user = req.kauth.grant.access_token.content.preferred_username;
  res.send(`<h1>Welcome to the intranet, ${user}!</h1>`);
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Intranet app listening on http://localhost:${PORT}`));
