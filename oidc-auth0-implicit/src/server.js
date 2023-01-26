const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const express = require('express');
const handlebars = require('express-handlebars');
const path = require('path');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const request = require('request-promise');
const session = require('express-session');
const query_string = require('querystring');

// loading env vars from .env file
require('dotenv').config();

const nonceCookie = 'auth0rization-nonce';
let oidcProviderInfo;

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser(crypto.randomBytes(16).toString('hex')));
app.use(
  session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false
  })
);
app.engine('handlebars', handlebars());
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/profile', (req, res) => {
  const { idToken, decodedIdToken } = req.session;
  res.render('profile', {
    idToken,
    decodedIdToken
  });
});

app.get('/login', (req, res) => {
  const authorizationEndpoint = oidcProviderInfo['authorization_endpoint'];
  const responseType = 'id_token';
  const scope = 'openid email profile';
  const clientID = process.env.CLIENT_ID;
  const redirectUri = 'http://localhost:3000/callback';
  const responseMode = 'form_post';
  const nonce = crypto.randomBytes(16).toString('hex');

  const options = {
    maxAge: 1000 * 60 * 15,
    httpOnly: true, // The cookie only accessible by the web server
    signed: true // Indicates if the cookie should be signed
  };

  const authURL = `${authorizationEndpoint}?${query_string.stringify({
    response_mode: responseMode,
    response_type: responseType,
    scope: scope,
    client_id: clientID,
    redirect_uri: redirectUri,
    nonce: nonce
  })}`;

  console.log(authURL);

  res.cookie(nonceCookie, nonce, options).redirect(authURL);
});

app.post('/callback', async (req, res) => {
  const nonce = req.signedCookies[nonceCookie];
  delete req.signedCookies[nonceCookie];

  const { id_token } = req.body;

  const decodedToken = jwt.decode(id_token, { complete: true });

  const kid = decodedToken.header.kid;

  const jwkClient = jwksClient({
    jwksUri: oidcProviderInfo['jwks_uri']
  });

  jwkClient.getSigningKey(kid, (err, key) => {
    const signingKey = key.publicKey || key.rsaPublicKey;

    const verifiedToken = jwt.verify(id_token, signingKey);

    console.log('======> ', verifiedToken);

    const {
      nonce: decodedNonce,
      aud: audience,
      exp: expirationDate,
      iss: issuer
    } = verifiedToken;
    const currentTime = Math.floor(Date.now() / 1000);
    const expectedAudience = process.env.CLIENT_ID;
    if (
      audience !== expectedAudience ||
      decodedNonce !== nonce ||
      expirationDate < currentTime ||
      issuer !== oidcProviderInfo['issuer']
    ) {
      // send an unauthorized http status
      return res.status(401).send();
    }

    req.session.decodedIdToken = verifiedToken;
    req.session.idToken = id_token;

    res.redirect('/profile');
  });
});

app.get('/to-dos', async (req, res) => {
  res.status(501).send();
});

app.get('/remove-to-do/:id', async (req, res) => {
  res.status(501).send();
});

const { OIDC_PROVIDER } = process.env;
const discEnd = `https://${OIDC_PROVIDER}/.well-known/openid-configuration`;
request(discEnd)
  .then(res => {
    oidcProviderInfo = JSON.parse(res);
    console.log(oidcProviderInfo);
    app.listen(3000, () => {
      console.log(`Server running on http://localhost:3000`);
    });
  })
  .catch(error => {
    console.error(error);
    console.error(`Unable to get OIDC endpoints for ${OIDC_PROVIDER}`);
    process.exit(1);
  });
