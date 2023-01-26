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
  const { accessToken } = req.session;

  console.log(accessToken);

  const logoutUrl = `https://${
    process.env.OIDC_PROVIDER
  }/v2/logout?${query_string.stringify({
    returnTo: 'http://localhost:3000/logout'
  })}`;

  res.render('profile', {
    accessToken,
    logoutUrl
  });
});

app.get('/login', async (req, res) => {
  const codeExchangeOptions = {
    grant_type: 'client_credentials',
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    audience: process.env.API_IDENTIFIER
  };
  try {
    let codeExchangeResponse = await request.post(
      `https://${process.env.OIDC_PROVIDER}/oauth/token`,
      { form: codeExchangeOptions }
    );
    // console.log(typeof codeExchangeResponse);
    req.session.accessToken = JSON.parse(codeExchangeResponse)['access_token'];
    return res.redirect('profile');
  } catch (ex) {
    console.log(ex.toString());
    return res.status(500).json({ message: ex.toString() });
  }
});

app.get('/to-dos', async (req, res) => {
  const delegatedRequestOptions = {
    url: 'http://localhost:3001',
    headers: {
      Authorization: `Bearer ${req.session.accessToken}`
    }
  };

  try {
    const delegatedResponse = await request(delegatedRequestOptions);
    const toDos = JSON.parse(delegatedResponse);

    res.render('to-dos', {
      toDos
    });
  } catch (error) {
    res.status(error.statusCode).send(error);
  }
});

app.get('/logout', async (req, res) => {
  console.log('Logout called');
  req.session.destroy();
  res.redirect('/');
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
