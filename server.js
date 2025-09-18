const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const { User } = require('./model');

const app = express();

// === MongoDB Atlas Connection ===
// Be sure to replace `hello%40123` with your actual URL-encoded password if it's different.
const uri = "mongodb+srv://yashasvizadoo_db_user:hello%40123@scorven.i5bvsmg.mongodb.net/?retryWrites=true&w=majority&appName=SCORVEN";

mongoose.connect(uri)
  .then(() => console.log('✅ MongoDB Atlas connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// === Hardcoded secret (can be moved to .env) ===
const SESSION_SECRET = 'b6a31217bc14cb3faa9cab09a403f7d1d14a2d819974666d43d4189fff79623cd9661c01414c467e1ef6a1e6d308d1070e5e7517e05aca02423f7807c955118d';

// === Middleware ===
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));
app.use(passport.initialize());
app.use(passport.session());

// === Passport Local Strategy ===
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ username });
    if (!user) return done(null, false, { message: 'No user found' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return done(null, false, { message: 'Incorrect password' });

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (_id, done) => {
  const user = await User.findById(_id);
  done(null, user);
});

// === Middleware to protect routes ===
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/login.html');
};

// === Routes ===

// Registration
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      if (existingUser.username === username) {
        return res.status(400).json({ message: 'Username already taken. Please try a different one.' });
      }
      if (existingUser.email === email) {
        return res.status(400).json({ message: 'Email already used. Please try a different one.' });
      }
    }

    const hashed = await bcrypt.hash(password, 10);
    await User.create({ username, password: hashed, email, role: 'Observer' });
    
    // Corrected to send JSON for redirect
    res.status(200).json({ redirect: '/login.html' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'An unexpected error occurred during registration. Please try again.' });
  }
});

// Login
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(401).json({ message: 'Incorrect username or password.' });
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      return res.status(200).json({ redirect: '/explore.html' });
    });
  })(req, res, next);
});

// Page Routing
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

// New API route to get current user details
app.get('/api/me', (req, res) => {
  if (req.isAuthenticated()) {
    const { username, email, role } = req.user;
    res.json({ username, email, role });
  } else {
    res.status(401).json({ message: 'Not authenticated' });
  }
});

// New API routes for admin dashboard
app.get('/api/users', ensureAuthenticated, (req, res) => {
  if (req.user.role === 'Admin') {
    User.find({}, 'username email role')
      .then(users => res.json(users))
      .catch(err => res.status(500).json({ error: 'Failed to fetch users' }));
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
});

app.post('/api/grant', ensureAuthenticated, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { email, role } = req.body;
  try {
    const user = await User.findOneAndUpdate({ email }, { role }, { new: true });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json({ message: `Role for user ${user.username} updated to ${role}.` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user role' });
  }
});

app.post('/api/revoke', ensureAuthenticated, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { email } = req.body;
  try {
    const user = await User.findOneAndUpdate({ email }, { role: 'Observer' }, { new: true });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json({ message: `Role for user ${user.username} revoked to Observer.` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to revoke user role' });
  }
});

app.use((req, res) => {
  res.status(404).send('❌ Page not found');
});

// === Start server ===
app.listen(4000, () => {
  console.log('✅ SCORVEN server ready at http://localhost:4000');
});
