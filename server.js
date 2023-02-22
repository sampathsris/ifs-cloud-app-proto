
const express = require('express');
const session = require('express-session');
const http = require('http');
const passport = require('passport');
const { Issuer, Strategy } = require('openid-client');

// `urlcat` is used to safely construct URLs. See https://github.com/balazsbotond/urlcat
const urlcat = require('urlcat').default;

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
 * Identity provider needs to redirect the client back to the app after
 * authentication is performed. `appCallbackUrl` is for that purpose.
 */
const appCallbackUrl = urlcat(app_host, '/login/callback');

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

async function start() {
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
   * Once Passport.js authenticates the user, user claims will be stored
   * in the session, and we can extract the username.
   */
  passport.serializeUser((userinfo, done) => {
    console.log('Serialize', JSON.stringify(userinfo, null, 2));
    done(null, userinfo);
  });
  passport.deserializeUser((user, done) => {
    console.log('Deserialize', JSON.stringify(user, null, 2));
    done(null, user);
  });

  // Create an OpenID Connect Issuer object with the issuer URL
  console.log('Discovering OpenID Configuration using issuer', issuerUrl);
  const oidcIssuer = await Issuer.discover(issuerUrl);
  console.log('Discovered:', oidcIssuer.metadata);

  // Create an OpenID Client object using the issuer
  let client = new oidcIssuer.Client({
    client_id,
    client_secret,
    redirect_uris: [appCallbackUrl],
    response_types: ['code'],
  });

  /**
   * Create ODIC middleware to handle the authorization flow.
   * 
   * After the flow is finished, the verify function (which is
   * passed as the 2nd parameter when creating the Strategy object
   * below) receives objects containing the tokens and user info.
   */
  passport.use(
    'odic',
    new Strategy(
      {
        client,
        pasReqToCallback: true,
      },
      (tokenSet, userinfo, done) => {
        const allInfo = {
          tokenSet,
          userinfo,
          claims: tokenSet.claims(),
        };

        console.log('Verifying ODIC Strategy', allInfo);

        // Save the required information in the session
        return done(null, allInfo);
      },
    ),
  );

  // Login
  app.get(
    '/login',
    (req, res, next) => {
      console.log('/login');

      // If already authenticated, redirect to Homepage
      if (req.isAuthenticated()) {
        console.log('redirecting to /');
        return res.redirect('/');
      }
      
      next();
    },

    // This middleware initiates the login flow
    passport.authenticate('odic', {
      scope: 'openid',
    }),
  );

  app.get(
    '/login/callback',
    (_req, _res, next) => {
      /**
       * This handler is really not needed. It's just there to
       * detect and print the /login/callback route in console. The
       * actual work is done by the middleware from
       * `passport.atuhenticate` call below.
       */
      console.log('/login/callback');
      next();
    },

    /**
     * This is where the redirect from identity provider will be
     * redirected. Depending on the parameters, passport can decide
     * whether authentication succeeded or not. Then the handler
     * will redirect accoring to `successRedirect` and `failureRedirect`.
     */
    passport.authenticate('odic', {
      successRedirect: '/user',
      failureRedirect: '/',
    }),
  );

  // Homepage
  app.get(
    '/',
    (req, res) => {
      console.log('/');

      if (req.isAuthenticated()) {
        res.send('<a href="/logout">Log Out</a>');
      } else {
        res.send('<a href="/login">Log In</a>');
      }
    },
  );

  // User page
  app.get(
    '/user',
    (req, res) => {
      console.log('/user');

      if (!req.isAuthenticated()) {
        console.log('redirecting to /');
        return res.redirect('/');
      }

      const user = req.session.passport.user.preferred_username;
      res.header('Content-Type', 'text/html');
      res.send(
        `<a href="/">Home</a>
        <br />
        Logged in as ${user}.`);
    },
  );

  // Logout
  app.get(
    '/logout',
    (req, res, next) => {
      console.log('/logout');

      // If not authenticated, redirect to Homepage
      if (!req.isAuthenticated()) {
        console.log('redirecting to /');
        return res.redirect('/');
      }

      /**
       * Construct the OpenID end session URL using `client.endSessionUrl`.
       * The URL needs an id_token_hint, which should be a previously used
       * id_token. We can explicitly pass an id_token, or otherwise, 
       * `client.endSessionUrl` can find it from a token set. We previously
       * saved the token set in the session in the ODIC verifier function.
       * We can now retrieve the token set from the session.
       * 
       * It also requires a redirect url after the Identity Provider logs
       * the user out. We will redirect to homepage.
       */
      res.redirect(client.endSessionUrl({
        id_token_hint: req.user.tokenSet.id_token,
        post_logout_redirect_uri: app_host,
      }));
      
      /**
       * We also need to logout from passport. Even though we destroyed
       * our session with Identity Provider, passport does not know this.
       * Logging out from passport will clear req.user and destron the
       * Express.js session.
       */
      req.logout(err => {
        if (err) {
          return next(err);
        }
      });
    },
  );

  const httpServer = http.createServer(app);

  httpServer.listen(port, () => {
    console.log(`HTTP Server running on port ${port}`);
  });
}

start();
