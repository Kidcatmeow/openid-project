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
  console.log(decodedIdToken);
  res.render('profile', {
    idToken,
    decodedIdToken
  });
});

// app.get('/login', (req, res) => {
//   res.status(501).send();
// });

/* 2.Initiating the AUthentication Process
 The new /login endpoint is issuing an HTTP 302 (redirect) response to the caller, indicating 
that they must go to the authorization server with the parameters that the constants above defined. 
With that in place, if you restart the application, you will be able to click on the login link to check if 
the redirect is working properly. If everything works as expected, you will end up seeing the login page 
on your OpenID Connect provider.*/

app.get(`/login`, (req, res) => {
  // define constants for the authorization request
  // The authorization URL where you will redirect users
  const authorizationEndpoint = oidcProviderInfo[`authorization_endpoint`];
  // The response type your app expects from the provider
  /* 'id_token' because you want confimation that the user authenticated sucessfully 
      and you want to get the information directly from authorization process*/
  const responseType = `id_token`;
  // The information you want to learn about users authenticating
  // 'openid' only get information that users are logged in and a sub claim with their identifier on the provider.
  const scope = `openid email profile picture`;
  // The identifier that the provider attributes to your app
  const clientID = process.env.CLIENT_ID;
  // Where the provider will redirect users after the authentication process
  const redirectUri = `http://localhost:3000/callback`;
  // How your application will get the ID Token for the end-user
  /* inform the OIDC provider that you want your app to get the response back 
  from it (in this case, the id_token) in the body of an HTTP POST request. */

  const responseMode = `form_post`;
  // A random string that helps your app prevent replay attacks
  const nonce = crypto.randomBytes(16).toString(`hex`);
  // define a signed cookie containing the nonce value
  const options = {
    maxAge: 1000 * 60 * 15,
    httpOnly: true, // The cookie only accessible by the web server
    signed: true // Indicates if the cookie should be signed
  };

  // add cookie to the response and issue a 302 redirecting user
  res
    .cookie(nonceCookie, nonce, options)
    .redirect(
      authorizationEndpoint +
        `?response_mode=` +
        responseMode +
        `&response_type=` +
        responseType +
        `&scope=` +
        scope +
        `&client_id=` +
        clientID +
        `&redirect_uri=` +
        redirectUri +
        `&nonce=` +
        nonce
    );
});

/* 3.Handling the Authentication Callback 
  After  users login, OpenID Connect provider will redirect them back to the URL you passed as redirectURL 
  parameter of authorization request. 
  Since you asked the provider to use form_post as the responseType, the 
  authentication server will generate an ID Token, embed it in an HTML form, and render it on the enduser browser. The page that the provider renders will also include a script that will post the HTML form 
  automatically, as soon as it gets rendered */

// app.post('/callback', async (req, res) => {
//   res.status(501).send();
// });

/* With these modifications in place, when a user calls this endpoint (as the result of a successful 
authentication), the new version of it will create a constant that holds the value of the nonce generated 
for the authorization request.  */

app.post(`/callback`, async (req, res) => {
  // take nonce from cookie
  const nonce = req.signedCookies[nonceCookie];

  // delete nonce
  delete req.signedCookies[nonceCookie];

  // take ID Token posted by the user
  const { id_token } = req.body;

  // decode token
  const decodedToken = jwt.decode(id_token, { complete: true });

  // get key id
  const kid = decodedToken.header.kid;

  // get public key
  const client = jwksClient({
    jwksUri: oidcProviderInfo[`jwks_uri`]
  });

  client.getSigningKey(kid, (err, key) => {
    const signingKey = key.publicKey || key.rsaPublicKey;
    // verify signature & decode token
    const verifiedToken = jwt.verify(id_token, signingKey);
    // check audience, nonce, and expiration time
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
      issuer !== oidcProviderInfo[`issuer`]
    ) {
      // send an unauthorized http status
      return res.status(401).send();
    }
    req.session.decodedIdToken = verifiedToken;
    req.session.idToken = id_token;
    // send the decoded version of the ID Token
    res.redirect(`/profile`);
  });
});

app.get('/to-dos', async (req, res) => {
  res.status(501).send();
});

app.get('/remove-to-do/:id', async (req, res) => {
  res.status(501).send();
});

// app.listen(3000, () => {
//   console.log(`Server running on http://localhost:3000`);
// });

/* 1. Fetching Information from the Discovery Endpoint
   Intergrate the application with OpenID Connect Provider
   For starters, you will need to make your application issue a request 
   to the Discovery Endpoint to get information from your provider 
   
   to acheive this, you need to nest the call tp app.listen inside a code that retrieves
   information about OpenID Connect provider
   
   The idea is that, since the app needs this 
   information to enable users to authenticate, you can‘t let the server listen to users‘ requests until you 
   get these data*/
const { OIDC_PROVIDER } = process.env;
//issues HTTP GET request to a path under OpenID Connect Provider
const discEnd = `https://${OIDC_PROVIDER}/.well-known/openid-configuration`;
request(discEnd)
  .then(res => {
    //if the provider fulfills request correctly
    //application parse response into JavaScript object
    oidcProviderInfo = JSON.parse(res);
    app.listen(3000, () => {
      //get string response from the application
      console.log(`Server running on http://localhost:3000`);
    });
  })
  .catch(error => {
    //if application is unable to fetch provider data
    console.error(error);
    //log error with falure code process.exit(1)
    console.error(`Unable to get OIDC endpoints for ${OIDC_PROVIDER}`);
    process.exit(1);
  });
