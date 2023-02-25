
import express from 'express';
import session from 'express-session';
import http from 'http';
import passport from 'passport';
import { Issuer, Strategy } from 'openid-client';

// `urlcat` is used to safely construct URLs. See https://github.com/balazsbotond/urlcat
import urlcat from 'urlcat';

// `chalk` is for pretty text in the console
import chalk from 'chalk';

/**
 * Certain values are (sometimes optionally) constructed from certain
 * environment variables. These variables could be set directly on the
 * environment, or on a .env file.
 */
const port = process.env.PORT || 8080;
const app_host = process.env.APP_HOST || `http://localhost:${port}`;
const ifs_system_url = process.env.IFS_SYSTEM_URL;
const ifs_namespace = process.env.IFS_NAMESPACE;
const client_id = process.env.CLIENT_ID;
const client_secret = process.env.CLIENT_SECRET;
const session_secret = process.env.SESSION_SECRET ||
  'replace_this_with_a_proper_and_secure_secret';

/**
 * Routes.
 */
const APP_ROUTE_ROOT = '/';
const APP_ROUTE_LOGIN = '/login';
const APP_ROUTE_LOGIN_CALLBACK = '/login/callback';
const APP_ROUTE_USER = '/user';
const APP_ROUTE_LOGOUT = '/logout';

/**
 * Identity provider needs to redirect the client back to the app after
 * authentication is performed. `appCallbackUrl` is for that purpose.
 */
const appCallbackUrl = urlcat(app_host, APP_ROUTE_LOGIN_CALLBACK);

/**
 * Everything starts with the issuer URL. Knowing the issuer URL allows
 * anyone to find the OpenID configuration of the identity provider. This
 * takes the following form:
 *   - If IFS System URL is: https://acme.ifs.cloud, and
 *   - Customer Namespace is: acmeprod
 *   - https://acme.ifs.cloud/auth/realms/acmeprod
 */
const issuerUrl = urlcat(ifs_system_url, '/auth/realms/:ifs_namespace', {
  ifs_namespace
});

// Create an Express.js app
const app = express();

// Create a session to preserve login status and user info
app.use(session({
  secret: session_secret,
  resave: false,
  saveUninitialized: false,
}));

// Initialize Passport.js
app.use(passport.initialize());

// `passport.session()` middleware saves the user in the request object
app.use(passport.session());

/**
 * This middleware is just for verbosity. It will display server requests
 * and the authentication status at the time of the request. Otherwise,
 * this is unnecessary.
 */
app.use((req, _res, next) => {
  console.log(
    chalk.green(req.method),
    chalk.yellow(req.originalUrl),
    req.isAuthenticated()
      ? chalk.green('Authenticated')
      : chalk.red('Not Authenticated')
  );
  next();
});

/**
 * Once Passport.js authenticates the user, user claims will be stored
 * in the session, and we can extract the username.
 */
passport.serializeUser((userinfo, done) => {
  console.log(chalk.cyan('Serialized User Info'));
  console.log('--------------------------------------');
  console.log(userinfo);
  console.log('--------------------------------------');
  done(null, userinfo);
});
passport.deserializeUser((userinfo, done) => {
  console.log(chalk.cyan('Deserialized User Info'));
  console.log('--------------------------------------');
  console.log(userinfo);
  console.log('--------------------------------------');
  done(null, userinfo);
});

// Create an OpenID Connect Issuer object with the issuer URL
console.log(
  chalk.blue('Discovering OpenID Configuration using issuer'),
  chalk.magenta(issuerUrl),
);
const oidcIssuer = await Issuer.discover(issuerUrl);
console.log(chalk.cyan('Discovered OpenID Configuration'))
console.log('--------------------------------------');
console.log(oidcIssuer.metadata);
console.log('--------------------------------------');

// Create an OpenID Client object using the issuer
let client = new oidcIssuer.Client({
  client_id,
  client_secret,
  redirect_uris: [appCallbackUrl],
  response_types: ['code'],
});

const PASSPORT_STRATEGY_NAME = 'oidc';

/**
 * Create OIDC middleware to handle the authorization flow.
 * 
 * After the flow is finished, the verify function (which is
 * passed as the 2nd parameter when creating the Strategy object
 * below) receives objects containing the tokens and user info.
 */
passport.use(
  PASSPORT_STRATEGY_NAME,
  new Strategy(
    {
      client,
      pasReqToCallback: true,
    },
    (tokenSet, userinfo, done) => {
      console.log(chalk.cyan('Verifying OIDC Strategy'))

      console.log('--------------------------------------');
      console.log(chalk.cyan('tokenSet'))
      console.log('--------------------------------------');
      console.log(tokenSet);
      console.log('--------------------------------------');
      console.log(chalk.cyan('userinfo'))
      console.log('--------------------------------------');
      console.log(userinfo);
      console.log('--------------------------------------');
      console.log(chalk.cyan('claims'))
      console.log('--------------------------------------');
      console.log(tokenSet.claims());
      console.log('--------------------------------------');

      /**
       * This sort of says that the result of authentication is
       * the TokenSet and the UserInfo. This result will eventually
       * be passed to `passport.serialize` (declared above). There,
       * we chose to save all this information in the session. The
       * result is, we will be able to get token information and
       * user information from any route from this point onwards.
       */
      return done(null, {
        tokenSet,
        userinfo,
      });
    },
  ),
);

/**
 * This function simply sends a redirect to the user for a given path,
 * but at the same time prints the redirect to the console.
 */
const verboseRedirect = (res, path) => {
  console.log(
    chalk.magenta('redirecting to'),
    chalk.yellow(path),
  );

  return res.redirect(path);
};

// Login
app.get(
  APP_ROUTE_LOGIN,
  (req, res, next) => {
    // If already authenticated, redirect to Homepage
    if (req.isAuthenticated()) {
      return verboseRedirect(res, APP_ROUTE_ROOT);
    }

    /**
     * We are not actually redirecting to authorization URL. But under
     * the hood, the passport middleware will be doing that. This is
     * just for verbosity.
     */
    console.log(
      chalk.magenta('redirecting to'),
      chalk.yellow(client.authorizationUrl()),
    );

    next();
  },

  /**
   * This middleware initiates the authentication flow. It will redirect
   * the user to the authorization endpoints of the identity provider.
   */
  passport.authenticate(PASSPORT_STRATEGY_NAME, {
    scope: 'openid',
  }),
);

/**
 * This is where the redirect from identity provider will be
 * redirected. Depending on the parameters, passport can decide
 * whether authentication succeeded or not. Then the handler
 * will redirect accoring to `successRedirect` and `failureRedirect`.
 */
app.get(
  APP_ROUTE_LOGIN_CALLBACK,
  passport.authenticate(PASSPORT_STRATEGY_NAME, {
    successRedirect: APP_ROUTE_USER,
    failureRedirect: APP_ROUTE_ROOT,
  }),
);

// Homepage
app.get(
  APP_ROUTE_ROOT,
  (req, res) => {
    if (req.isAuthenticated()) {
      res.send(`<a href="${APP_ROUTE_LOGOUT}">Log Out</a>`);
    } else {
      res.send(`<a href="${APP_ROUTE_LOGIN}">Log In</a>`);
    }
  },
);

// User page
app.get(
  APP_ROUTE_USER,
  async (req, res) => {
    if (!req.isAuthenticated()) {
      return verboseRedirect(res, APP_ROUTE_ROOT);
    }

    /**
     * We can use the user information and token information
     * saved in the session.
     */
    const user = req.user.userinfo.upn;

    /**
     * The following should create a URL in the form of:
     *   https://acme.ifs.cloud/main/ifsapplications/projection/v1/UserHandling.svc/Users('USERID')?$select=Description
     * 
     * Using this URL and an access token, we should be able to send an HTTP
     * request to the IFS instance, which will treat it as an authenticated
     * request (due to the presence of the token), and reply us back with the
     * user's description. Of course, this requires that user we're logged in
     * with has permissions (at the least, read only) to the projection
     * `Userhandling.svc`.
     */
    const userResourcePath = `/main/ifsapplications/projection/v1/UserHandling.svc/Users('${
      // For `UserHandling.svc`, user names need to be uppercase.
      user.toUpperCase()
    }')`;
    const userResourceUrl = urlcat(
      ifs_system_url,
      userResourcePath,
      { '$select': 'Description' },
    );

    // We can get the access token from the session
    const accessToken = req.user.tokenSet.access_token;

    console.log(
      chalk.blue('Requesting resource'),
      chalk.yellow(userResourceUrl),
      chalk.green(accessToken),
    );

    /**
     * Client.requestResource will send a request to the provided URL
     * along with the access token. It returns (a Promise that contains)
     * the result of the call in the `body` property, as a Buffer (a
     * binary object that contains some data).
     */
    const { body: userResourceBody } = await client.requestResource(
      userResourceUrl,
      accessToken,
    );

    /**
     * The buffer with the user data needs to be converted to a string
     * before we can use it. The result will be a JSON string, which then
     * has to be parsed.
     */
    const userResource = JSON.parse(userResourceBody.toString('utf8'));
    console.log(userResource);

    res.header('Content-Type', 'text/html');
    res.send(`
      <a href="${APP_ROUTE_ROOT}">Home</a>
      <br />
      <p>Logged in as ${user} (${userResource.Description})</p>.
    `);
  },
);

// Logout
app.get(
  APP_ROUTE_LOGOUT,
  (req, res, next) => {
    // If not authenticated, redirect to Homepage
    if (!req.isAuthenticated()) {
      return verboseRedirect(res, APP_ROUTE_ROOT);
    }

    /**
     * Construct the OpenID end session URL using `client.endSessionUrl`.
     * The URL needs an id_token_hint, which should be a previously used
     * id_token. We can explicitly pass an id_token, or otherwise, 
     * `client.endSessionUrl` can find it from a token set. We previously
     * saved the token set in the session in the OIDC verifier function.
     * We can now retrieve the token set from the session.
     * 
     * It also requires a redirect url after the Identity Provider logs
     * the user out. We will redirect to homepage.
     */
    const end_session_url = client.endSessionUrl({
      id_token_hint: req.user.tokenSet.id_token,
      post_logout_redirect_uri: app_host,
    });
    verboseRedirect(res, end_session_url);

    /**
     * We also need to logout from passport. Even though we destroyed
     * our session with Identity Provider, passport does not know this.
     * Logging out from passport will clear req.user and destroy the
     * Express.js session.
     */
    req.logout(err => {
      if (err) {
        console.error(chalk.red('Error destroying passport session'));
        console.error(err);

        return next(err);
      }
    });
  },
);

const httpServer = http.createServer(app);

httpServer.listen(port, () => {
  console.log(chalk.bold.blue(`HTTP Server running on port ${port}`));
});
