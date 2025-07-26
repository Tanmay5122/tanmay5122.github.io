const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

// === Hardcoded secrets (you can later switch to .env for security) ===
const SESSION_SECRET = 'b6a31217bc14cb3faa9cab09a403f7d1d14a2d819974666d43d4189fff79623cd9661c01414c467e1ef6a1e6d308d1070e5e7517e05aca02423f7807c955118d';
const GOOGLE_CLIENT_ID = '82591552385-gtppb72u6mluhk8oi9i1ms302mcsdh93.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = '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';
const GOOGLE_CALLBACK_URL = 'http://localhost:4000  /auth/google/callback';

// === Static files ===
app.use(express.static(path.join(__dirname, 'public')));

// === Session ===
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // set to true if using HTTPS
}));

// === Passport ===
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: GOOGLE_CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// === Middleware to protect routes ===
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/');
};

// === Routes ===
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/index.html' }),
  (req, res) => {
    res.redirect('/explore.html');
  }
);

app.get('/explore.html', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'explore.html'));
});

app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect('/explore.html');
  } else {
    res.redirect('/index.html');
  }
});

app.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => {
      res.redirect('/');
    });
  });
});

app.use((req, res) => {
  res.status(404).send('❌ Page not found');
});

// === Start server ===
app.listen(4000, () => {
  console.log('✅ SCORVEN server ready at http://localhost:4000');
});
