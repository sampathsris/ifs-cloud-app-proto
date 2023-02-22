
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const http = require('http');
const passport = require('passport');
const { Issuer, Strategy } = require('openid-client');
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

const appCallbackUrl = urlcat(app_host, '/login/callback');
const issuerUrl = urlcat(ifs_system_url, '/auth/realms/:ifs_namespace', {
  ifs_namespace
});

async function start() {
  const app = express();

  app.use(cookieParser());
  app.use(express.urlencoded({
    extended: true,
  }));

  app.set('views', path.join(__dirname, 'views'));
  app.set('view engine', 'ejs');
  app.use(express.static(path.join(__dirname, 'public')));

  app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
  }));

  app.use(passport.initialize());
  app.use(passport.session());

  passport.serializeUser((user, done) => {
    console.log(JSON.stringify(user, null, 2));
    done(null, user);
  });
  passport.deserializeUser((user, done) => {
    console.log(JSON.stringify(user, null, 2));
    done(null, user);
  });

  const oidcIssuer = await Issuer.discover(issuerUrl);
  let client = new oidcIssuer.Client({
    client_id,
    client_secret,
    redirect_uris: [appCallbackUrl],
    response_types: ['code'],
  });

  passport.use(
    'odic',
    new Strategy(
      {
        client,
        pasReqToCallback: true,
      },
      (tokenSet, userinfo, done) => {
        console.log('Verifying ODIC Strategy', { tokenSet, userinfo });
        return done(null, { tokenSet, userinfo });
      }
    ));

  app.get(
    '/login',
    (_req, _res, next) => {
      console.log('Login Handler Started');
      next();
    },
    passport.authenticate('odic', {
      scope: 'openid',
    }),
  );

  app.get(
    '/login/callback',
    (req, res, next) => {
      const handler = passport.authenticate('odic', {
        successRedirect: '/user',
        failureRedirect: '/',
      });
      handler(req, res, next);
    },
  );

  app.get(
    '/',
    (req, res) => {
      if (req.isAuthenticated()) {
        res.send('<a href="/logout">Log Out</a>');
      } else {
        res.send('<a href="/login">Log In</a>');
      }
    },
  );

  app.get(
    '/user',
    (req, res) => {
      if (!req.isAuthenticated()) {
        return res.redirect('/');
      }

      const user = req.session?.passport?.user?.userinfo.preferred_username;
      res.header('Content-Type', 'text/html');
      res.send(
        `<a href="/">Home</a>
        <br />
        Logged in as ${user}.`);
    },
  );

  app.get(
    '/logout',
    (req, res) => {
      if (!req.isAuthenticated()) {
        return res.redirect('/');
      }

      console.log('Logout Handler Started');
      res.redirect(urlcat(oidcIssuer.end_session_endpoint, {
        post_logout_redirect_uri: app_host,
        id_token_hint: req.user.tokenSet.id_token,
      }));
      req.session.destroy();
    },
  );

  const httpServer = http.createServer(app);

  httpServer.listen(port, () => {
    console.log(`HTTP Server running on port ${port}`);
  });
}

start();
