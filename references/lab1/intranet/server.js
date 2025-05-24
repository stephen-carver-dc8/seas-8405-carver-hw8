const express = require('express');
const session = require('express-session');
const Keycloak = require('keycloak-connect');

const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://localhost:8080';
const KEYCLOAK_KEY = process.env.KEYCLOAK_KEY || 'KEYCLOAK_KEY';
const REALM = process.env.KEYCLOAK_REALM || 'CentralIAM';
const CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || 'intranet';

const memoryStore = new session.MemoryStore();

const app = express();
app.use(session({
  secret: KEYCLOAK_KEY,
  resave: false,
  saveUninitialized: true,
  resource: "",
  store: memoryStore
}));

const keycloak = new Keycloak({ store: memoryStore }, {
  realm: REALM,
  'auth-server-url': `${KEYCLOAK_URL}`,
  resource: CLIENT_ID,
  'public-client': true,
});

app.use(keycloak.middleware());

app.get('/', (req, res) => {
  res.send(`
    <h1>Welcome to the Intranet Start Page</h1>
    <p><a href="/authed">Go to Authenticated Page</a></p>
  `);
});

app.get('/authed', keycloak.protect(), (req, res) => {
  //const user = req.kauth.grant.access_token.content.preferred_username;
  //res.send(`<h1>Welcome to the intranet, ${user}!</h1>`);
  res.send(`<h1>Welcome to the intranet!</h1>`);
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Intranet app listening on http://localhost:${PORT}`));
